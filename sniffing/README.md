Oto propozycja mocno przebudowanego i skoncentrowanego na procesie klasyfikacji pliku `README.md`. Usunąłem sekcje techniczne i cele, a w ich miejsce dodałem szczegółowy opis logiki przepływu danych oraz hybrydowego podejścia ML.

---

# OMLBPC: System Klasyfikacji Ruchu Sieciowego w Czasie Rzeczywistym

Projekt koncentruje się na **automatycznej klasyfikacji pakietów sieciowych** przy użyciu hybrydowego podejścia uczenia maszynowego. System został zaprojektowany tak, aby umożliwić zarówno masowe zbieranie danych treningowych, jak i błyskawiczną klasyfikację na żywo poprzez przełączanie się między różnymi modelami predykcyjnymi.

## 1. Architektura Przepływu Danych (Data Pipeline)

Poniższy schemat obrazuje, jak pakiet przechodzi od karty sieciowej do ostatecznej klasyfikacji:



### Etapy przetwarzania:
* **Przechwytywanie i Etykietowanie (Online):** Sniffer przechwytuje pakiety, a moduł `PortMap` w czasie rzeczywistym sprawdza, który proces systemowy (np. Spotify) otworzył dane połączenie, przypisując pakietowi etykietę klasy.
* **Buforowanie Przepływów (Flow Cache):** Aby uniknąć przeciążenia procesora, system zapamiętuje przynależność strumieni (5-tuple) do aplikacji przez określony czas (TTL), co pozwala na natychmiastowe etykietowanie kolejnych pakietów w tym samym połączeniu.
* **Ekstrakcja Cech:** Każdy pakiet jest konwertowany na wektor cech. W zależności od wybranego modelu, system wyciąga statystyki przepływu lub surowe bajty payloadu.

## 2. Hybrydowa Metodologia Klasyfikacji

System wspiera dwa równoległe podejścia do analizy ruchu:

### Ścieżka A: Klasyfikacja Statystyczna (Random Forest)
* **Cechy (Features):** Wykorzystuje zagregowane dane, takie jak czas między przybyciem pakietów (`inter_arrival_ms`), długość pakietów IP, flagi TCP oraz rozmiar okna.
* **Zaleta:** Niskie wymagania obliczeniowe, idealne do szybkiej selekcji ruchu w standardowych warunkach sieciowych.

### Ścieżka B: Klasyfikacja Głębokiego Uczenia (CNN)
* **Cechy (Features):** Analizuje surowe bajty nagłówków i payloadu (pierwsze *N* bajtów pakietu).
* **Zaleta:** Skuteczna w wykrywaniu wzorców w ruchu szyfrowanym, gdzie tradycyjne statystyki mogą być niewystarczające.



## 3. Praca Offline i Ekstrakcja Cech
Dzięki modułowej budowie, system pozwala na przetwarzanie zgromadzonego wcześniej ruchu:
* **Zapis surowy:** Ruch może być zapisywany do plików `.pcap` w celu późniejszej analizy.
* **Ekstrakcja Batch:** Specjalny moduł `offline_extractor.py` pozwala na ponowne przetworzenie plików PCAP na formaty CSV lub macierze gotowe do nauki nowych modeli ML/CNN bez konieczności ponownego nagrywania ruchu.

## 4. Przełączanie Modeli w Trybie Online
Główny moduł sniffera został zaprojektowany z myślą o elastyczności. W trybie predykcji online system umożliwia:
* Ładowanie wytrenowanych wag modeli z plików zewnętrznych.
* Dynamiczne przełączanie między modelem Random Forest a CNN w trakcie pracy, co pozwala na porównanie wydajności i dokładności obu podejść "na żywo".

---

### Struktura Modułowa Projektu:
* `capture_utils.py`: Obsługa interfejsów i systemowe mapowanie portów.
* `feature_extractor.py`: Logika zamiany pakietów na dane numeryczne dla ML.
* `main.py`: Koordynator sniffera, łączący zbieranie danych z silnikiem klasyfikacji.
* `diagnose.py`: Weryfikacja poprawności uprawnień i widoczności procesów przed startem.
