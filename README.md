1.Materiały interaktywne i VM

Pierwsze kolejności mamy przedstawione gdzie znajdują się nasze plik z którymi będziemy pracoweać.
następnie musimy uruchomic ten skrypt ```sudo ./traffic-generator.sh``` aby móc przechwytywać nasz ruch na żywo.

Task 1:
Przejdź do  folderu Task-Exercises i uruchom polecenie „ ./.easy.sh ” i zapisz dane wyjściowe.
Wystarczy abyśmy uruchomili nasz skrypt za pomocą ./.easy.sh i otrzymamy odpowiedź na nasze pytanie.
```ubuntu@ip-10-10-245-149:~/Desktop/Task-Exercises$ ./.easy.sh - Too Easy!```

1.Wprowadzenie do IDS/IPS

Task 1: Który tryb Snort może pomóc Ci zatrzymać zagrożenia na komputerze lokalnym?
W tym przypadku będzie to: HIPS 
```HIPS aktywnie chroni przepływ ruchu z pojedynczego urządzenia końcowego```

Task 2:Który tryb Snort może pomóc w wykrywaniu zagrożeń w sieci lokalnej?
Będzie to: NIDS
```rejestrowanie/usuwanie pakietów uznanych za  złośliwe  zgodnie z regułami zdefiniowanymi przez użytkownika.```

Task 3: Który tryb Snort może pomóc wykryć zagrożenia na komputerze lokalnym?
Będzie to: HIDS 
```atrzymuje zagrożenia, kończąc połączenie```

Task 4:Który tryb Snort może pomóc Ci zatrzymać zagrożenia w sieci lokalnej?
Będzie to: NIPS

Task 5:Który tryb snort działa podobnie do trybu NIPS?
Będzie to: NBA 

Task 6:Jaki to rodzaj NIPS-a według oficjalnego opisu snorta?
Będzie to: full-blown
```"Snort can be deployed inline to stop these packets, as well. Snort has three primary uses: As a packet sniffer like tcpdump, as a packet logger — which is useful for network traffic debugging, or it can be used as a full-blown network intrusion prevention system. Snort can be downloaded and configured for personal and business use alike."```

Task 7:Okres treningowy NBA jest również znany jako ...
```systemy oparte na zachowaniu wymagają okresu szkolenia (znanego również jako „baselining”)```


2.Pierwsza interakcja ze Snortem
Task 1:Uruchom instancję Snort i sprawdź numer kompilacji.
Aby się tego dowiedzieć wystarczy uruchomić polecenie ```snort -V``` zobacz poniżej

![image](https://github.com/user-attachments/assets/7d5a9af1-9d20-452b-9a5b-e6fd0382718f)

Obok version możemy zobaczyć build i to własnie będzie nasz numer kompilacji, czyli w tym przypadku 149.

Task 2: Przetestuj bieżącą instancję za pomocą pliku „/etc/snort/snort.conf” i sprawdź, ile reguł zostało załadowanych przy bieżącej kompilacji.
Aby to sprawdzić w pierwszej koleności musimy użyć polecenia ```sudo snort -c /etc/snort/snort.conf -T``` i na załączony poniżej zrzucie ekranu możesz to zobaczyć:

![image](https://github.com/user-attachments/assets/b0c8f05e-4c61-41ee-9744-9c289590f370)

Snort rules read, w tym przypadku będzie to: 4151.

Task 3: Przetestuj bieżącą instancję za pomocą pliku „/etc/snort/snortv2.conf” i sprawdź, ile reguł zostało załadowanych przy bieżącej kompilacji.
Czyli tutaj ponownie używamy tego samego polecenia co w zadaniu drugim tylko podmieniamy snort.conf na snortvs2.conf

No i możemy zobaczyć na załączony zrzucie ekranu poniżej, że jest to tylko jeden:

![image](https://github.com/user-attachments/assets/e2f7c39c-749d-4674-8c9a-fc3fce624541)

3.Tryb działania 1: Tryb sniffera
Podobnie jak tcpdump, Snort ma różne flagi umożliwiające przeglądanie różnych danych na temat pobieranego pakietu.

```

Parametr	Opis
-w	Verbose. Wyświetla dane wyjściowe TCP /IP w konsoli.
-D	Wyświetl dane pakietu (ładunek).
-mi	Wyświetl nagłówki warstwy łącza danych (TCP/IP/ UDP /ICMP). 
-X	Wyświetl pełne szczegóły pakietu w formacie HEX.
-I	Ten parametr pomaga zdefiniować konkretny interfejs sieciowy do nasłuchiwania/podsłuchiwania. Gdy masz wiele interfejsów, możesz wybrać konkretny interfejs do podsłuchiwania. 
```

4.Tryb działania 2: Tryb rejestratora pakietów

Task 1:
Zbadaj ruch przy użyciu domyślnego pliku konfiguracyjnego  w trybie ASCII.
sudo snort -dev -K ASCII -l .
Uruchom skrypt generatora ruchu i wybierz  „TASK-6 Exercise” . Poczekaj, aż ruch się zakończy, a następnie zatrzymaj instancję Snort. Teraz przeanalizuj podsumowanie wyników i odpowiedz na pytanie.
sudo ./traffic-generator.sh
Teraz powinieneś mieć logi w bieżącym katalogu. Przejdź do folderu „ 145.254.160.237 ”. Jaki jest port źródłowy używany do połączenia portu 53?

Wykonajmy wszystkie kroki, jakie są zamieszczone w zadaniu pierwszym i przejdźmy odrazu do szczegółów, czyli przejdźmy do katalogu 145.254.160.237

![image](https://github.com/user-attachments/assets/cd45ecc8-32e5-4538-a0a2-5302639a872c)

I możemy zobaczyć, że port żródłowy do połączenia jest to 3009 

Task 2:
Użyj  snort.log.1640048004 
Odczytaj plik snort.log za pomocą Snort; jaki jest identyfikator IP 10. pakietu?
snort -r snort.log.1640048004 -n 10

Ponownie użyj poleceń zamieszczony powyżej, poniżej możesz zobaczyć na zrzucie PID 10 pakietu:

![image](https://github.com/user-attachments/assets/81f23f5c-b09a-4067-8b80-eb36f721f166)

Jest to: 49313

Task 3:
Przeczytaj plik „ snort.log.1640048004”  za pomocą Snort. Jaki jest adres referencyjny czwartego pakietu?

Musimy nieco zmodyfikować nasze polecenie dodając na końcu -X czyli będzie to wyglądać następująco: ```snort -r snort.log.1640048004 -n 10 -X```
Ukaże nam się coś takiego:
```
0x01E0: 52 65 66 65 72 65 72 3A 20 68 74 74 70 3A 2F 2F  Referer: http://
0x01F0: 77 77 77 2E 65 74 68 65 72 65 61 6C 2E 63 6F 6D  www.ethereal.com
0x0200: 2F 64 65 76 65 6C 6F 70 6D 65 6E 74 2E 68 74 6D  /development.htm
0x0210: 6C 0D 0A 0D 0A                                   l....
```
Odpowiedno odfiltrowywując to uzyskamy: http://www.ethereal.com/development.html

Task 4:Przeczytaj plik „ snort.log.1640048004”  za pomocą Snort; jaki jest numer potwierdzenia ósmego pakietu?
Teraz ponownie wróćmy do naszego starego polecenia: ```snort -r snort.log.1640048004 -n 8``` tylko 10 podmieniłem na 8 aby dotrzeć szybko do tego pakietu, może zobaczyć numer ACK na poniższym zrzucie ekranu:

![image](https://github.com/user-attachments/assets/2b10fe7a-3465-4634-b950-e4bf83c0f219)

Czyli to będzie: 0x38AFFFF3

Task 5:Przeczytaj plik „ snort.log.1640048004” za pomocą Snort; jaka jest liczba pakietów „TCP port 80” ?
Użyłem w tym przypadku tego polecania ```snort -r snort.log.1640048004 'tcp and port 80' | wc -l``` aby wyświetlił nam ile jest tych pakietów, jest to 41.

6.Tryb działania 3: IDS/IPS






