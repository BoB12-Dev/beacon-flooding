LDLIBS += -lpcap

all: beacon-flood

airodump: beacon-flood.c

clean:
	rm -f beacon-flood *.o