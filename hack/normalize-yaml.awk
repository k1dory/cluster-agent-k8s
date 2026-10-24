# Drops blank lines that directly precede a document separator, so `helm template` output is
# byte-identical across Helm minors (3.17+ prints an empty line before each `---`).
{ lines[NR] = $0 }
END {
  for (i = 1; i <= NR; i++) {
    if (lines[i] == "" && i < NR && lines[i+1] == "---") continue
    print lines[i]
  }
}
