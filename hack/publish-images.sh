#!/usr/bin/env bash
# make publish-images: the three images of one commit, built for linux/amd64, pushed, signed and
# recorded. Publishing is an explicitly configured action, not a check (docs/ci-contract.md,
# rule 5): a fork publishes to its own registry with its own key, and nothing here reads a CI
# provider's variables.
#
#   IMAGE_REPO          required: where the images go, e.g. ghcr.io/OWNER/REPO; each image is
#                       IMAGE_REPO/<sandboxd|sandboxctl|agent>
#   COMMIT              the commit being published (default: HEAD); it must be HEAD of a clean
#                       checkout, since the build context is the working tree
#   SOURCE_URL          optional: org.opencontainers.image.source (GHCR links the package to the
#                       repository named here)
#   REGISTRY_USER, REGISTRY_PASSWORD
#                       optional: docker login to IMAGE_REPO's registry first
#   COSIGN_PRIVATE_KEY, COSIGN_PASSWORD
#                       the signing key (cosign generate-key-pair) and its password; without a
#                       key the run fails, unless PUBLISH_UNSIGNED=1 says unsigned is intended
#   PUBLISH_MANIFEST    where the record goes (default .ci/publish/images.json)
#
# The tag is sha-<first 12 characters of COMMIT> and nothing else: no `latest`, so a reference
# names one build. A tag is immutable here: when it already exists (a re-run for the same
# commit), the image is not rebuilt; its digest is recorded and signed if no signature from
# cosign.pub's key is there yet. The manifest names image, digest, arch, commit and the harness
# versions of the agent image (hack/ci/versions.env); `make verify-images` checks it.
. "$(dirname "$0")/ci/lib.sh"
cd "$ci_root"

[ -n "${IMAGE_REPO:-}" ] || ci_die "publish: IMAGE_REPO is required (e.g. ghcr.io/OWNER/REPO)"
# Registries want lower case (GHCR refuses an owner spelled as GitHub shows it).
IMAGE_REPO=$(printf '%s' "${IMAGE_REPO%/}" | tr '[:upper:]' '[:lower:]')
head=$(git rev-parse HEAD)
COMMIT=${COMMIT:-$head}
[ "$COMMIT" = "$head" ] || ci_die "publish: COMMIT $COMMIT is not the checkout's HEAD ($head)"
dirty=$(git status --porcelain)
[ -z "$dirty" ] || ci_die "publish: the checkout has changes the images would carry but $COMMIT does not:
$dirty"
signed=true
if [ -z "${COSIGN_PRIVATE_KEY:-}" ]; then
  [ "${PUBLISH_UNSIGNED:-}" = 1 ] || ci_die "publish: COSIGN_PRIVATE_KEY is not set; set it (and COSIGN_PASSWORD), or PUBLISH_UNSIGNED=1 to publish unsigned on purpose"
  signed=false
fi
command -v python3 >/dev/null || ci_die "publish: python3 is required (the manifest)"
ci_docker
docker buildx version >/dev/null 2>&1 || ci_die "publish: docker buildx is required"
cosign=$(ci_cosign)
export COSIGN_YES=true

tag=sha-${COMMIT:0:12}
platform=linux/amd64
manifest=${PUBLISH_MANIFEST:-$ci_root/.ci/publish/images.json}
work=$ci_root/.ci/publish/work
rm -rf "$work" && mkdir -p "$work" "$(dirname "$manifest")"
created=$(date -u +%Y-%m-%dT%H:%M:%SZ)

if [ -n "${REGISTRY_PASSWORD:-}" ]; then
  [ -n "${REGISTRY_USER:-}" ] || ci_die "publish: REGISTRY_PASSWORD without REGISTRY_USER"
  printf '%s' "$REGISTRY_PASSWORD" | docker login "${IMAGE_REPO%%/*}" -u "$REGISTRY_USER" --password-stdin >/dev/null
fi

# A builder of the docker-container driver: the docker driver cannot push the provenance
# attestation buildx records next to each image (mode=max: the build's materials and arguments).
builder=agent-sandbox-publish
docker buildx inspect "$builder" >/dev/null 2>&1 || docker buildx create --name "$builder" --driver docker-container >/dev/null

# pushed_digest REF prints the digest REF names in the registry, and fails when it names none.
pushed_digest() {
  local json
  json=$(docker buildx imagetools inspect "$1" --format '{{ json .Manifest }}' 2>/dev/null) || return 1
  printf '%s' "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["digest"])' 2>/dev/null
}

# publish NAME DOCKERFILE [TARGET]: build and push NAME, or find it already pushed; append its
# line to the record.
publish() {
  local name=$1 file=$2 target=${3:-} ref digest meta args=()
  ref=$IMAGE_REPO/$name:$tag
  echo "== $name: $ref"
  if digest=$(pushed_digest "$ref"); then
    echo "$ref exists ($digest): an immutable tag is not rebuilt"
  else
    meta=$work/$name.json
    [ -n "$target" ] && args+=(--target "$target")
    [ "$name" = agent ] && read -r -a harness <<<"$("$ci_dir/versions.sh" build-args)" && args+=("${harness[@]}")
    [ -n "${SOURCE_URL:-}" ] && args+=(--label "org.opencontainers.image.source=$SOURCE_URL")
    # ${args[@]+...}: an empty array is "unbound" to bash 3.2's set -u (macOS).
    docker buildx build --builder "$builder" --platform "$platform" -f "$file" ${args[@]+"${args[@]}"} \
      --label "org.opencontainers.image.revision=$COMMIT" --label "org.opencontainers.image.created=$created" \
      --provenance=mode=max --metadata-file "$meta" --push -t "$ref" .
    digest=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["containerimage.digest"])' "$meta")
  fi
  case "$digest" in sha256:*) ;; *) ci_die "publish: $name: no digest for $ref" ;; esac
  if $signed; then
    if "$cosign" verify --key cosign.pub "$IMAGE_REPO/$name@$digest" >/dev/null 2>&1; then
      echo "$name@$digest is signed by cosign.pub's key already"
    else
      "$cosign" sign --key env://COSIGN_PRIVATE_KEY "$IMAGE_REPO/$name@$digest"
    fi
  fi
  printf '%s %s\n' "$name" "$digest" >> "$work/digests"
}

publish sandboxd images/sandboxd/Dockerfile
publish sandboxctl images/sandboxd/Dockerfile sandboxctl
publish agent images/agent/Dockerfile

python3 - "$work/digests" "$manifest" "$IMAGE_REPO" "$tag" "$COMMIT" "$platform" "$created" "$signed" \
  "$CLAUDE_CODE_VERSION" "$CODEX_VERSION" "$COSIGN_VERSION" <<'PY'
import json, sys
digests, out, repo, tag, commit, platform, created, signed, claude, codex, cosign = sys.argv[1:]
images = []
for line in open(digests):
    name, digest = line.split()
    images.append({"image": f"{repo}/{name}", "name": name, "tag": tag, "digest": digest,
                   "ref": f"{repo}/{name}@{digest}", "arch": platform})
json.dump({"commit": commit, "tag": tag, "created": created, "repository": repo,
           "signed": signed == "true", "public_key": "cosign.pub", "cosign": cosign,
           "harness": {"claude-code": claude, "codex": codex}, "images": images},
          open(out, "w"), indent=2)
PY
rm -rf "$work"
cat "$manifest"
echo "publish: $tag: ok (manifest $manifest)"
