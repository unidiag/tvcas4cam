# TVCAS4CAM

TVCAS4CAM is a program that allows to open an encrypted TVCAS3/4 MPEG-TS stream.

## How to use

Install need libraries:

```
root@nuc:/~# apt install libssl-dev libdvbcsa-dev
```

Clone this code to your server:

```
root@nuc:/~# git clone https://github.com/unidiag/tvcas4cam
root@nuc:/~# cd ./tvcas4cam
```

Then edit smartcard data and UDP-in/UDP-out in the file **tvcas4cam.c**.

Compile and run:

```
root@nuc:/~# chmod +x ./run.sh
root@nuc:/~# ./run.sh
```

## Decoding internal messages

![Screenshot tvcas4cam](https://github.com/tvcas4cam/blob/main/Screenshot.jpg)
