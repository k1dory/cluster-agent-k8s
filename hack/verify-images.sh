#!/usr/bin/env bash
# make verify-images: the images a publish recorded are signed by cosign.pub's key, and their tags
# still name the digests recorded (an immutable tag that moved is a failure, not a new version).
# Needs no registry credentials for public packages: this is what a puller can check.
#
#   PUBLISH_MANIFEST  the record of make publish-images (default .ci/publish/images.json)
#   COSIGN_PUBLIC_KEY the key to check against (default cosign.pub)
. "$(dirname "$0")/ci/lib.sh"
cd "$ci_root"
manifest=${PUBLISH_MANIFEST:-$ci_root/.ci/publish/images.json}
key=${COSIGN_PUBLIC_KEY:-$ci_root/cosign.pub}
[ -f "$manifest" ] || ci_die "verify: no manifest at $manifest (make publish-images writes it; the publish workflow keeps it as an artifact)"
[ -f "$key" ] || ci_die "verify: no public key at $key"
command -v python3 >/dev/null || ci_die "verify: python3 is required"
cosign=$(ci_cosign)

# name tag digest image, one line per image.
python3 -c '
import json, sys
m = json.load(open(sys.argv[1]))
if not m.get("signed"):
    sys.exit("verify: the manifest records an unsigned publish")
for i in m["images"]:
    print(i["name"], i["tag"], i["digest"], i["image"])
' "$manifest" > "$ci_root/.ci/verify-images.list"
while read -r name tag digest image; do
  # Verifying the tag (not the digest) makes cosign resolve it: the digest it reports signed must
  # be the one recorded.
  out=$("$cosign" verify --key "$key" "$image:$tag" 2>/dev/null) || ci_die "verify: $image:$tag carries no valid signature from $key"
  seen=$(printf '%s' "$out" | python3 -c '
import json, sys
print(" ".join(sorted({s["critical"]["image"]["docker-manifest-digest"] for s in json.load(sys.stdin)})))')
  [ "$seen" = "$digest" ] || ci_die "verify: $image:$tag resolves to $seen, the manifest recorded $digest"
  echo "$name: $image:$tag = $digest, signed"
done < "$ci_root/.ci/verify-images.list"
rm -f "$ci_root/.ci/verify-images.list"
echo "verify: images of $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["commit"])' "$manifest"): ok"
