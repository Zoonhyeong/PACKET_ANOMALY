#!/usr/bin/env bash
# CTU-13 시나리오 3개(전체 트래픽 pcap + 플로우 라벨) 다운로드 -> eval/data/sXX/
# 출처: Stratosphere Lab, CTU (CC-BY) https://www.stratosphereips.org/datasets-ctu13
set -euo pipefail
cd "$(dirname "$0")"
B=https://mcfp.felk.cvut.cz/publicDatasets
for spec in "46 capture20110815-2" "48 capture20110816-2" "52 capture20110818-2"; do
  set -- $spec
  mkdir -p data/s$1
  curl -fL -o data/s$1/$2.binetflow "$B/CTU-Malware-Capture-Botnet-$1/detailed-bidirectional-flow-labels/$2.binetflow"
  curl -fL -o data/s$1/$2.truncated.pcap.bz2 "$B/CTU-Malware-Capture-Botnet-$1/$2.truncated.pcap.bz2"
  bunzip2 -f data/s$1/$2.truncated.pcap.bz2
done
