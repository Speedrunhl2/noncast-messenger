# noncast-messenger 
Chat-Launcher v.0.0.1a

#### Compile&Launch

1. ```sudo apt install tor obfs4proxy build-essential libssl-dev libncurses5-dev libncursesw5-dev libsodium-dev``` <<<installing required packets.
3. ```tor --hash-password <your password>``` <<< creating hash of password to our Tor ControlPanel.
4. ```sudo nano /etc/tor/torrc``` <<< start editing tor config files.
(your torrc file should contain next:)
```
...
ControlPort 9051
HashedControlPassword <here put the hash you have got from hashing command>
SocksPort 9050
UseBridges 1
ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy

Bridge <your bridge>
Bridge <your bridge>
```
5. ```tor``` <<< simply launch your tor (if it's already launched, restart it by ```sudo systemctl restart tor```).
6. ```openssl genrsa -out server.key 2048``` <<< generate a 2048-bit RSA private key.
7. ```openssl req -new -x509 -key server.key -out server.crt \ -days 365 -subj "/C=US/ST=Test/L=Local/O=DevOrg/OU=Dev/CN=localhost"```<<< creating self-signed certificate for our server
8. In src/server/tor.c change "PUT PASSWORD HERE" to actual password from your Tor ControlPanel so server code can use it and generate .onion address.
9. Build whole code by command ```make launcher```.

####Usage
1. Run ```./launcher```
2. Write username and password.
3. Now you have two options:
[1] - Create server. <-will create .onion address and your device will turn into chatroom server. The client will need .onion address to connect to your chatroom.
[2] - Connect to server. <-you need to put .onion address here to connect to the chatroom.
>>>After connection you can type text to others in chatroom and also use commands:
(Hint : all commands start by '/'. If you type command without slash it'll be ignored):
/exit - sends to server an EXIT ask then disconnects client from server.
/file <filename> - sends file to others in chatroom <WIP>.
/sticker <stickername> - sends big sticker in chat <WIP>.
