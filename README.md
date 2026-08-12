# DRIP_PoC_PEE
UNDER DEVELOPMENT
This repository contains the files of the PoC developed as part of my Master Thesis.
The PoC utilizes a ESP32 to broadcast the drone equivalent messages via wi-fi only (i couldn't make it work with the wifi and bluetooth modules active at the same time).
Them, the PC capture the packages via serial port (constrains with my PC wifi board, but i could see it using DroneRemoteID apps for android, so should be fine) using python scripts to decode and assert if the messages are valid or not (it can display some errors messages to help understand why the message was consider invalid).
As now the "drone" have it pub and private key hardcoded to facilitate test and experiments. It's expected to implement secure ways to store the privkey in the drone afterwards.


#OBSERVERFILES--------------------------------------------------------------------------------
Inside the ObserverFiles folder there is some interesting pythons scripts that is used in this project context:

ARDUINO_LOGGER.PY
The arduino_logger.py file is a python script that creates a text file named data_log.txt with the data that the arduino is transmitting in it's serial port.
This Project uses two ESP32 boards, one to broadcast the drone data and another as a sniffer.
The COM PORT of the sniffer one's is read by the arduino_logger.py that generates then the capture.txt, that is as txt file with the drone messages.
The sniffer board exist because the PC that i am using in development dosen't support the promiscuous mode of the wifiboard.
To use the arduino_logger the command is:

python3 arduino_logger.py --port COM3 --baud 921600 -o capture.txt

Where COM3 is the COM port where my sniffer is connected, the baud choose was to garantee that all the Sniffer messages was transmitted in time without overloading the communication speed and the capture.txt is the name that you want your log file to have.


OBSERVER.PY
To utilize the observer.py it's necessary to have a txt file with the packages that your drone have transmitted. It's accept some diferents types of formatation, wherever, it should display a message if it dosen't understand your formating, avoiding thus to declare it wrong just because it had not the correct formating

Run on your ESP32 the serial log captured with the sniffer:
python3 observer.py capture.txt

Run verbose (shows every decoded message):
python3 observer.py capture.txt --verbose

Enable DET↔key binding check (E-DET-02) — pass our public key:
python3 observer.py capture.txt --pubkey 8B65B265A496E32046CFA378B5A5FB2E877A97723E557CB5F0D21848BFE94477 #-> This is one of the public key that I are using, you can change to yours
	
Run on the test vectors file (the quickest demo):
python3 observer.py bytesonlytest2.txt

Run the full self-test (no file needed):
python3 make_vectors.py --selftest

Some others commands that you can use with the observer.py file:

--keyring FILE        'DET_HEX PUBKEY_HEX' per line
--no-builtin-keys     drop the 3 bench identities
--list-keys           show the keyring and exit
--pubkey HEX          now a wildcard: any DET without an entry


Early i had a pure python implementation that was taking too long to run but was bring correct results.
Now, when the observer starts it verify the old implementing alongside with the new for a now package and a corrupted know one too and return that everything agrees.
If you want you can run the purê python version but be aware that it was taking hours to return a 3 drone 12 minutes flight.
Proof it's equivalent, on your data: observer.py capture.txt and --pure-python produce byte-identical output. --pure-python is there whenever you want to re-run a result against the reference.


MAKE_MAP.PY
This python script generates a .html file to display graphically the path of the drone using the captured data of a .txt file. 
This file was made using as template the cyber-defence-campus/RemoteIDReceiver repository
To run the make_map.py you can use this command:

python3 make_map.py your_log.txt -o my_flight.html --title "Test flight 3"

The your_log.txt is the txt file that you want the graphic representation, the my_flight.html is the name that you want for the product (the map generated).

#---------------------------------------------------------------------------------------------

#LEGACY_DRIP_BROADCAST_RID--------------------------------------------------------------------


This folder will be keep in the Project for now so i can run some test if deemed necessary later for my thesis writing but will be discontinued later since it is a older version with some old problems that dosen't exist anymore.

In this folder you can find every file that is used by the ESP32.

The arduino library used are:
-Crypto by Rhys Weatherley [0.4.0]
-NimBLE-Arduino by h2zero [2.5.0] (i really don't remember if there is some bluetooth dead code but it was utilized during development and is still installed)
-Seeed_Arduino_mbedtls by Peter Yang [3.0.2]

The board used is the "ESP32 Dev Module" but i belive that it work with almost any ESP32 board

There are 23 flight's path at the user disposition to use, everyone of them is near the Interlagos Race Track. 

When reseted (be by the button or by power on) the ESP32 start broadcasting the flight path number 0. By typing "stop" in the serial monitor it display the bellow information

[Playback] Choose a flight to start transmitting again:
             <number>   select and start that flight
             reset      replay the current flight
             list       show all flights
===========================================================
[Playback] Available flights:
   0 : 0M63J2T001H037         270 pts  (~7.8 min real time)  <= selected
   1 : 0M6CG9QR0A0FD6         843 pts  (~124.6 min real time)
   2 : 1ZNBK5900C00A8        1032 pts  (~77.0 min real time)
   3 : 3NZCHCP0043PS1         330 pts  (~1.8 min real time)
   4 : 4GCCK6QR0B0QRZ         595 pts  (~2894.3 min real time)
   5 : 5FSCK320115HYT         513 pts  (~5.9 min real time)
   6 : F4XF82391006Q24L       135 pts  (~0.7 min real time)
   7 : F5BKB246700F00DV       177 pts  (~3.7 min real time)
   8 : F5FJC248L00D6GD3       765 pts  (~1549.5 min real time)
   9 : F5FJC248M00DXTG9       378 pts  (~2.9 min real time)
  10 : F67QC234U01429M1       180 pts  (~1069.1 min real time)
  11 : F6Z9A23BHML35V6J      1062 pts  (~13.3 min real time)
  12 : F6Z9A24AAML33B85      1074 pts  (~2927.7 min real time)
  13 : F6Z9C23A7003A3HF       117 pts  (~0.7 min real time)
  14 : F6Z9C23AB003BTNG       408 pts  (~2.4 min real time)
  15 : F6Z9C23AR003DHVF        93 pts  (~0.5 min real time)
  16 : F6Z9C24B60035ER9       916 pts  (~9.3 min real time)
  17 : F8PJC246L0004BAG       285 pts  (~4.0 min real time)
  18 : F986C254E0020E5T       732 pts  (~22.8 min real time)
  19 : F9DEC258M029H723       264 pts  (~6.7 min real time)
  20 : F9DEC259A029P8S8       209 pts  (~5.7 min real time)
  21 : KCG0021GGR             237 pts  (~3.0 min real time)
  22 : MissionAlpha          1019 pts  (~0.0 min real time)
  23 : encrypted              194 pts  (~2901.8 min real time)
[Playback] Type a number to select, or 'list' | 'info' | 'next' | 'reset'.

I this implementation the pub and priv key are hardcoded and can be easily changed.
For each of this flight path is possible to determine an different pub and private key but as it is now they all shake the same pair.
#---------------------------------------------------------------------------------------------
#DRIP_Fleet_Broadcast-------------------------------------------------------------------------

In this folder you can find every file that is used by the ESP32.

The arduino library used are:
-Crypto by Rhys Weatherley [0.4.0]
-NimBLE-Arduino by h2zero [2.5.0] (i really don't remember if there is some bluetooth dead code but it was utilized during development and is still installed)
-Seeed_Arduino_mbedtls by Peter Yang [3.0.2]

The board used is the "ESP32 Dev Module" but i belive that it work with almost any ESP32 board

There are 27 flight's path at the user disposition to use, everyone of them is near the Interlagos Race Track. 

When reseted (be by the button or by power on) the ESP32 start broadcasting the flight path number 0. By typing "stop" in the serial monitor it display the bellow information

[Playback] Choose a flight to start transmitting again:
             <number>   select and start that flight
             reset      replay the current flight
             list       show all flights
===========================================================
[Playback] Available flights:
   0 : 0M63J2T001H037             270 pts  (~7.8 min real time)
   1 : 0M6CG9QR0A0FD6             843 pts  (~124.6 min real time)
   2 : 1ZNBK5900C00A8            1032 pts  (~77.0 min real time)
   3 : 3NZCHCP0043PS1             330 pts  (~1.8 min real time)
   4 : 4GCCK6QR0B0QRZ             595 pts  (~2894.3 min real time)
   5 : 5FSCK320115HYT             513 pts  (~5.9 min real time)
   6 : F4XF82391006Q24L           135 pts  (~0.7 min real time)
   7 : F5BKB246700F00DV           177 pts  (~3.7 min real time)
   8 : F5FJC248L00D6GD3           765 pts  (~1549.5 min real time)
   9 : F5FJC248M00DXTG9           378 pts  (~2.9 min real time)  
  10 : F67QC234U01429M1           180 pts  (~1069.1 min real time)
  11 : F6Z9A23BHML35V6J          1062 pts  (~13.3 min real time)
  12 : F6Z9A24AAML33B85          1074 pts  (~2927.7 min real time)
  13 : F6Z9C23A7003A3HF           117 pts  (~0.7 min real time)
  14 : F6Z9C23AB003BTNG           408 pts  (~2.4 min real time)
  15 : F6Z9C23AR003DHVF            93 pts  (~0.5 min real time)
  16 : F6Z9C24B60035ER9           916 pts  (~9.3 min real time)
  17 : F8PJC246L0004BAG           285 pts  (~4.0 min real time)
  18 : F986C254E0020E5T           732 pts  (~22.8 min real time)
  19 : F9DEC258M029H723           264 pts  (~6.7 min real time)
  20 : F9DEC259A029P8S8           209 pts  (~5.7 min real time)
  21 : KCG0021GGR                 237 pts  (~3.0 min real time)
  22 : MissionAlpha              1019 pts  (~0.0 min real time)
  23 : encrypted                  194 pts  (~2901.8 min real time)
  24 : F6Z9A24AAML33B85-1108      329 pts  (~11.7 min real time)
  25 : F6Z9A24AAML33B85-1109a    1465 pts  (~12.8 min real time)
  26 : F6Z9A24AAML33B85-1109b    2700 pts  (~116.7 min real time)
[Playback] Type a number to select, or 'list' | 'info' | 'next' | 'reset'.

To controle the fleet you have the following commands:

fleet <N>                 -> N drones, flights auto-assigned 0..N-1
fleet <N> same <flight>   -> N drones all replaying the same flight
fleet set <slot> <flight> -> assign one slot
fleet list | fleet stop | fleet start

#---------------------------------------------------------------------------------------------
#SNIFFER--------------------------------------------------------------------------------------

This is the code for the second ESP32 board with the sollemn objective to capture the messages of the broadcast and them display it in the serial communication port
It's is Always capting the information but it will only record it when the Arduino_loggers is called:

python arduino_logger.py --port COM3 --baud 921600 -o capture.txt

If you prefers you can also transform the txt file in na pcap versions with the bellow comand:

"C:\Program Files\Wireshark\text2pcap.exe" -t "%H:%M:%S.%f" -l 105 capture.txt capture.pcap

#OUTDATED-------------------------------------------------------------------------------------

This folder contains only two files, an .ino one and a .py.
These files is to utilize a second ESP32 board to capture the packages that the first board (the "drone") is broadcasting and make available to the PC via serial interface so the wireshark can receive the packages like it was capturing using he wi-fi board.

There is no guarantee that this contraption work as intended and the last test using it was months ago but it is provided in this repository as there is chance that it will be necessary later and to permit contributions from others.

To use it run the command below:
python bridge.py COM3 921600 | "C:\Program Files\Wireshark\Wireshark.exe" -k -i -