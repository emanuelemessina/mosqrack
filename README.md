# mosqrack
Simple multithreaded mosquitto hash cracker

## Usage

`mosqrack <passwd_file> <wordlist_file>`

- `passwd_file` : path to the passwd file generated by mosquitto_passwd.
- `worlist_file` : the path to a wordlist text file (one password per line).

## Build from source

OpenSSL lib and headers location must be specified in the solution.
\
The project is currently built with Visual Studio.

## License

Since this project contains parts of [mosquitto](https://github.com/eclipse/mosquitto) source code, it maintains the same license.
\
See [external/mosquitto/README](mosqrack/external/mosquitto/README).

## Author

	Emanuele Messina