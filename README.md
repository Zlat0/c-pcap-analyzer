# pcapan

Narzędzie CLI (C11, Linux) do analizy ruchu sieciowego z plików `.pcap` / `.pcapng` (TCP i UDP).
Generuje raport `report.pdf` oraz wykresy PNG, wykrywa m.in. skanowanie portów, SYN flood,
RST storm i UDP flood.

## Budowanie

```
sudo apt install build-essential cmake pkg-config libpcap-dev libcairo2-dev fonts-dejavu-core
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

## Uruchomienie

```
./build/pcapan -i samples/sample.pcap -o out/
```

Wynik: `out/report.pdf` i `out/charts/*.png`.

Opcje: `-i` plik wejściowy (można kilka), `-o` katalog wyjściowy, `-f` filtr BPF, `-b` szerokość
przedziału w sekundach, `-n` rozmiar rankingów, `--no-pdf`, `--no-png`, `-v`, `-q`, `-h`.

Przykładowy plik `samples/sample.pcap` można wygenerować poleceniem
`python3 scripts/gen_fixtures.py`.
.....

edited 22.11.2026 12:14
