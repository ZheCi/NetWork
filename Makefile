OBJE=main.o NetCard.o Sniffer.o Option.o
CC=g++
CFLAGS+=-c -Wall

sniffer:$(OBJE)
	$(CC) $^ -o $@ -lpcap

%.o:%.cpp
	$(CC) $(CFLAGS) $^ -o $@

rm:
	rm -r *.o
