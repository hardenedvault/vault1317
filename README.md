# Copyright (C) 2018-2023, [HardenedVault Limited](https://hardenedvault.net) 

# vault1317

A wicked messenger falls into adversity, But a faithful envoy brings healing. --- ???

ALERT: <pre>T H I S   I S   N O T   B U T C H E R   B A Y</pre>
--> [Vault1317 paper](https://hardenedvault.net/blog/2021-06-02-vault1317-thesis/) was written by neither academia bitch nor industry freak but a group of cypherpunks

## What is vault1317?
Vault1317 is a secure communication protocol that is designed to provide end-to-end encryption and protect metadata while preserving deniability. The protocol is based on the Signal Protocol, which is widely regarded as one of the most secure and privacy-preserving communication protocols available. Vault1317 extends the Signal Protocol by adding additional features such as metadata protection and deniability. Metadata protection is achieved through the use of additional handshaking protocols, which help to conceal the cryptographic identity of the sender and receiver, as well as other metadata associated with the communication.Deniability is achieved through the use of the symmetric encryption scheme with the consideration of deniability, as well asn the additional handshaking protocols mentioned before, which ensure that a sender can deny having sent a message if necessary, even if the message is intercepted or leaked.Vault1317 is a promising solution for those looking to communicate securely and privately while also protecting metadata and providing deniability of messages. 

## What problem will vault1317 address?
This project aims to solve several critical problems in modern communication:

While instant messaging tools such as Signal and WhatsApp have adopted good encryption, they still lack the ability to provide deniability, which is crucial for secure communication. If an attacker gains control of one of the parties or the server (such as Relay) and leaks chat content during communication between Alice and Bob, both parties can deny their chat content, making it difficult to hold anyone accountable for the breach. This project addresses this issue by implementing a provably secure deniability mechanism that ensures the authenticity of chat content while providing plausible deniability for the communicating parties.

Another critical issue in modern communication is metadata protection. During communication between Alice and Bob, their long-term identity public key is often exposed, making it easier for attackers to identify and track them. This project addresses this issue by concealing the long-term identity public key, ensuring that metadata remains private and secure.

Finally, this project aims to address the centralization of modern social media and instant messaging tools, which can make them vulnerable to censorship and surveillance. By adapting Vault1317 to a decentralized platform such as Nostr or XMPP, the project ensures that communication is not controlled by a single entity and that users can communicate freely and securely.

## What are the main differences between vault1317 and Signal, Matrix, and OTRv3/OTRv4?
The implementation of end-to-end encryption in Signal and Matrix is similar, both consisting mainly of three parts: the offline handshake protocol x3dh, the communication protocol double ratchet, and the out-of-order message recovery protocol sesami. The main difference between vault1317 and them is that vault1317 has designed new online and offline handshake protocols to conceal public keys, and more identity information is concealed within the encrypted channel.

OTRv3 was the first to implement public key conceal, but it could only be used for private chats and online handshakes, and it lacked compatibility with multiple clients and group chats.

OTRv4 plans to use the double ratchet scheme for communication (with different details from the above protocols), and it has online and offline handshake protocols, but for some reason, it has given up public key concealing while vault1317 has reintroduced this feature.

## Why is vault1317 has stronger deniability than Signal?
vault1317 is committed to achieving deniability and adapting to more use cases. Signal, for various reasons (including only considering centralized servers), only uses the X3DH offline handshake protocol, that is, it attaches a signed prekey bundle to the server, which loses deniability.

## Offline messages will reduce deniability in some sense. What solutions can vault1317 provide?
It is best to use online handshakes instead of offline messages. When the other party comes online, they will receive the first online handshake message and complete the online handshake automatically. After that, the communication between the two parties will have the strongest deniability.

## In a federation (such as XMPP) scenario where Alice and Bob communicate and go through a relay, does Bob's collusion with the relay mean a weakening of deniability?
vault1317 implements zero-knowledge proof in the form of ring signature, and although the relay can grasp some metadata (such as IP, traffic size information, etc.), Bob is unable to prove the communication content with Alice to a third party (Alice can deny and saying it was forged by Bob), so deniability is still maintained in this scenario.

## Can vault1317 do traffic obfuscation, such as implementing fixed packet sizes?
Packet-level traffic obfuscation should not be the responsibility of the vault1317 protocol (which handles messages of varying lengths), but should be implemented at the level below or  just above TLS (organizing data segments into streams, and then send as packets).

## Is it possible to use zk-SNARKs to remove the signature from the authentication process?
This is a good idea. Although a ring signature is a signature already has deniability. SNARKs can theoretically only allow Alice and Bob to authenticate each other but cannot prove to a third party. In the case of Bob betraying Alice, even if Bob reveals the signature (via Ring Signature) to Chris, he still cannot prove who actually spoke, it’s pretty much like Bob betraying Alice by leaking a set of polynomial equations to the 3rd party. In this scenario, ring signature is a more suitable zero-knowledge proof method than zk-SNARKs.

## Can vault1317 use the Secp256k1 ECC algorithm to achieve better compatibility with existing cryptocurrencies? If not, what is the best practice?
There is no need for a wallet to prove identity when sending and receiving messages. If identity association is required, a master-subkey relationship similar to OpenPGP can be used: the private key of the cryptocurrency serves as the master key, and the vault1317 authentication public key as the subkey is signed. However, it may be better to use two completely independent keys.

## Implementation & integration

|Application | Decentralized approach | Protocol |
|:-----------:|:-------------:|:-------:|
| Pidgin/[lurch1317](https://github.com/hardenedvault/lurch/blob/lurch1317/README-lurch1317.md)| Federation | XMPP/OMEMO|
| [Nostr/NIP-1317 (WIP)](https://github.com/nostr-protocol/nips/pull/591/files) | Relay       | Nostr |
| Veilsay (WIP)      | Relay         | Nostr |


## DEMO

Install the prerequisites:
```
apt install cmake clang protobuf-c-compiler check libssl-dev pkg-config libgcrypt20-dev libreadline-dev libglib2.0-dev libsqlite3-dev libevent-dev git
```

Update the submodules and build the demo:
```
git submodule update --init --recursive
make && make tests/testapp
```

### vault1317/signal-dakez protocol emulation

Initializing the server:
```
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:`pwd`/libsignal-protocol-c/build/src
cd tests
./testapp server vault0
------------------------------------------
[AXC INFO] axc_init_with_imp: initializing axolotl client
[AXC DEBUG] axc_init_with_imp: created and set axolotl context
[AXC DEBUG] axc_init_with_imp: set axolotl crypto provider
[AXC DEBUG] axc_init_with_imp: set locking functions
[AXC DEBUG] axc_init_with_imp: created store context
[AXC DEBUG] axc_init_with_imp: set store context
[AXC INFO] axc_init_with_imp: done initializing axc
[AXC INFO] axc_install: calling install-time functions
[AXC DEBUG] axc_install: created db if it did not exist already
[AXC ERROR] axc_db_property_get: Result not found (sqlite err: no more rows available)

[AXC DEBUG] axc_install: db does not need reset
[AXC DEBUG] axc_install: db needs init
[AXC DEBUG] axc_install: setting init status to AXC_DB_NEEDS_ROLLBACK (0)
[AXC DEBUG] axc_install: generated identity key pair
[AXC DEBUG] axc_install: generated registration id: 554296682
[AXC DEBUG] axc_install: generated pre keys
[AXC DEBUG] axc_install: generated signed pre key
[AXC DEBUG] axc_install: saved identity key pair
[AXC DEBUG] axc_install: saved registration id
[AXC DEBUG] axc_install: saved pre keys
[AXC DEBUG] axc_install: saved signed pre key
[AXC DEBUG] axc_install: initialised DB
[AXC DEBUG] axc_bundle_collect: entered
[AXC DEBUG] axc_bundle_collect: leaving
------------------------------------------
```

Client initiates an online key exchange:
```
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:`pwd`/libsignal-protocol-c/build/src
cd tests
./testapp client vault1 554296682@vault0
-------------------------------
press '[' and ']' to start online and offline handshaking respectively.
Message to send:Wrong msg before KeX
        Failed to encrypt message with err -1000                     press '[' and ']' to start online and offline handshaking respectively.
[AXC 4] Function IdakeAuthStart, at line 166 of file src/idake.c: 
msg IdakeKeyDigestMessage to send dumped as:
-------------------------------
(IdakeKeyDigestMessage 
39A45150ED6C8DCA960339B1DF2ED582#)573BF65AE4FE9AA3D7986C5BCBCB81BC29E88CCC97B707FE1E1BF17D47DFAD13CF5BD6973
 )
[AXC 4] Function Idake_handle_prekeymsg, at line 411 of file src/idake.c: 
msg IdakeMessage received dumped as:
-------------------------------
(IdakeMessage 
 (IdakePreKeyMessage 
  (prekey #05E447286A5C837672114272ED4201A133638A75BE8B625502F5E87DBF88FC9B46#)
  )
 )

-----------538 of file src/idake.c: 
msg IdakeIdKeyMessage to be encrypted as IdakeEncryptedIdKeyMessage::encidkey dumped as:
-----------------------------------------
(IdakeIdKeyMessage 
 (idkey #052ADFDC1FEB336806A12F1731829B8FD408E99AAE1B11E7E6E010A367160D4B73#)
 (regid "1841412435")
 )
47 of file src/idake.c: 
msg IdakeEncryptedIdKeyMessage to send dumped as:
-----------------------------------------
(IdakeEncryptedIdKeyMessage 
 (prekey #0592F2D59D87AA723AAC56A0C21C074DA7A281034B14041A03531289C9D6144441#)
 (encidkey #3E29D3C17C289A642A411B070814D7823BD08AE69BFC4358F806EA71B73A7CF0FB1C66E355E00CAC23B4ACEA0427DE26#)
 )                      ersidkmsg, at line 1186 of file src/idake.c: 
msg IdakeMessage received dumped as:
-------------------------------------
(IdakeMessage 
 (IdakeEncryptedRsIdKMessage 
  (encrsidkeymsg #41EA461344AD361317160803BE3E260DFE71DAC7EB1755BA98292940956C52E7B3378B918EE0F42BCB652E7FD80C8ADFA1D9549908C1F441F7A6DB7F5BB753BE390D6006ED4CB9471729CF5910AA5B53F97545FF557754206D898CB6DFCD3B7637B3A3ED31AA53CBC14525C15C247D3815CBFC867DDE205AD2EA07D9A191F2BC8C705B0CE1C0CE3AF1B346 of file src/idake.c: 949207177488C1C8F29C2DAC5EBB78BBFCA7477DC550C5952A3EECF7841FF7484F7DC74B3B2B15E4984655F1FB9D70A7#)
msg IdakeIdKeyMessage decrypted dumped as:
------------------------           ------
(dakeRsignedIdKeyMessage 
 (idkey #051781C6E776EC7CEF5E1912895F718874AEA0EADCF539D3E3D7CB5AEFF2D45252#)
 (regid "554296682")
 (rsig #CB9F5D7D51A6F019CFB947933888305160800212B0A1DBA6CE118398F502F00534407D7EF18477DEEFCA794708CBC4C9D8B06E9B29B96AF5DB7E766382EFB80DDC64A7C0792D2EEE2444DBFCBAECD78292429E39BEBE96A22DA0D86FC531F808842CF7F502B0C1CDC72C3176BF6EC047AA792080E748C1369DB09578B364630C5EF5470608006116B891AAF7102AA36CDEFEC8ECF3911DC1A605855 of file src/idake.c: 00D299CBF6D43446FF20F71A6D1C6AF3C102F3CCF809D795501#)
msg IdakeEncryptedRsigMessage to send dumped as:
------------------                 ------
(IdakeEncryptedRsigMessage 
 (encrsig #F1CA1A6FA12FB80574D8F520FBA2688760B98761E2ACA13724E82D4805477381D5DFF6EB1B37146F87DE56D1A633AD3B56829A7F8A53321DA40F30FD409772F8FE946ACA4AC86879C3C629AD6EAED7D3559D71647644CFE5FB1BD720B889056EE9C2BF795571FAD641E9E80A1E25F59AE78CB6596B5E85FEBEE0B40773EB7EDCB395A2C9EA03A79D624CDC08569A389CB86A6898F728EE698D671604B8E305D70B0B307EBE617E45C289F612A212F43BA47EA0102D34F5E243BA2517D8321ED6EC6CD9EEF277CFAE452CA01BFB7B0AFC#)
 )

-----------------------------------------

```

Client initiates an offline key exchange:
```
press '[' and ']' to start online and offline handshaking respectively.
[AXC 0] axc_pre_key_message_process_dake: not a pre key msg
Message from 554296682@vault0:
Message from 1841412435@vault1: 
     4] Function session_builder_process_pre_key_bundle_odake, at line 244 of file src/odake.c: 
msg session_pre_key_bundle fetched dumped as: 
-----------------------------------------
(session_pre_key_bundle 
 (registration_id "554296682")
 (device_id "554296682")
A0AA8B4ECB5F588A3639759A86BAD6594F0ED2A038D14F8E509D72D50B125#)
06F77564# re_key "0" #A660CA78D92C04B08BA4E456C32560F184C3044EB951C88FF7ACCF070
9DBF6D715BA461C567991ECA04#)#0D7EEB03A57D48C2D3469A92A4E4FAC47D1DB6561228FDCEF66D15C6A9D465A8A2B7647168725A9F11F51FCD3FAC894C25229A9
  )
Message to send:Do you know the way to vault1317?
         701 of file src/odake.c: 
msg IdakeEncryptedIdKeyMessage to send dumped as:
---------------------------------
(OdakePreKeyMessage 
 (prekey "1" #050600BA72A0D8193F66D30EAA3AC4022653BD31EB4E3BDFA71255438CD3F9BC5A#)
pkid "0")
C35F5C0DB3ECCD3E2C71EFF074CF5EE553EBBD8D0291F1C5525A9E1A91A3B5FF2489CEC8ED7CFF0DB350AD430D348C315F8DE7D1FBC955D2674D5F099D95C8F8182FEB785F3C0E98E7C12DD8A7D394D51140719A1B26345644245B4921873D423C695672F5A483127C74CEABAFDC2C8AB8BF67FDE40E8FAEC7FAB2A347BF1C74D2D5B47320FC3544684339FC380262636F539BD9AFBCFB9E5DB3C08AAF3C4FFB6FA64AFB84D867165C9DC3D60BBE7FA3EE92878A013D49D5FA54A56EF28D97B46972ADC7B1F1E6BD939853E328612D1AA3C7B596#) 
582BC8B7311684EE9D3E74D135E00356D963A254FC92218193893F8E145F9CE55F#)F88665BBB5E27421000180022307DD0A54F0EAAF5C780C13707010BE7C02D37D9607523F45
 )

-----------------------------------------
t1317?press '[' and ']' to start online and offline handshaking respectively.
[AXC 0] axc_pre_key_message_process_dake: not a pre key msg
Message from 554296682@vault0:
Message from 1841412435@vault1: Do you know the way to vault1317?

```

Switch back to the server:
```
[AXC DEBUG] The other end /tmp/vault1317/tests/1841412435@vault1 has connected the socket!
[AXC DEBUG] Function Idake_handle_kdgstmsg, at line 254 of file src/idake.c: 
msg IdakeMessage received dumped as:
-----------------------------------------
(IdakeMessage 
 (IdakeKeyDigestMessage 
  (digest #F9134B2FB854379CBC5AFB9F573BF65AE4FE9AA3D7986C5BCBCB81BC29E88CCC97B707FE1E1BF17D47DFAD13CF5BD69739A45150ED6C8DCA960339B1DF2ED582#)
  )
 )

-----------------------------------------

[AXC DEBUG] Function Idake_create_keymsg, at line 218 of file src/idake.c: 
msg IdakePreKeyMessage to send dumped as:
-----------------------------------------
(IdakePreKeyMessage 
 (prekey #05E447286A5C837672114272ED4201A133638A75BE8B625502F5E87DBF88FC9B46#)
 )

-----------------------------------------

[AXC DEBUG] Function Idake_handle_idkeymsg, at line 925 of file src/idake.c: 
msg IdakeMessage received dumped as:
-----------------------------------------
(IdakeMessage 
 (IdakeEncryptedIdKeyMessage 
  (prekey #0592F2D59D87AA723AAC56A0C21C074DA7A281034B14041A03531289C9D6144441#)
  (encidkey #3E29D3C17C289A642A411B070814D7823BD08AE69BFC4358F806EA71B73A7CF0FB1C66E355E00CAC23B4ACEA0427DE26#)
  )
 )

-----------------------------------------

[AXC DEBUG] Function Idake_handle_idkeymsg, at line 1113 of file src/idake.c: 
msg IdakeIdKeyMessage decrypted dumped as:
-----------------------------------------
(IdakeIdKeyMessage 
 (idkey #052ADFDC1FEB336806A12F1731829B8FD408E99AAE1B11E7E6E010A367160D4B73#)
 (regid "1841412435")
 )

-----------------------------------------

[AXC DEBUG] Function Idake_handle_idkeymsg, at line 1122 of file src/idake.c: 
msg IdakeIdKeyMessage to be encrypted as IdakeEncryptedIdKeyMessage::encrsidkeymsg dumped as:
-----------------------------------------
(dakeRsignedIdKeyMessage 
 (idkey #051781C6E776EC7CEF5E1912895F718874AEA0EADCF539D3E3D7CB5AEFF2D45252#)
 (regid "554296682")
 (rsig #CB9F5D7D51A6F019CFB947933888305160800212B0A1DBA6CE118398F502F00534407D7EF18477DEEFCA794708CBC4C9D8B06E9B29B96AF5DB7E766382EFB80DDC64A7C0792D2EEE2444DBFCBAECD78292429E39BEBE96A22DA0D86FC531F808842CF7F502B0C1CDC72C3176BF6EC047AA792080E748C1369DB09578B364630C5EF5470608006116B891AAF7102AA36CDEFEC8ECF3911DC1A605831D4B258D0FA76A6A03FF16D00D299CBF6D43446FF20F71A6D1C6AF3C102F3CCF809D795501#)
 )

-----------------------------------------

[AXC DEBUG] Function Idake_handle_idkeymsg, at line 1131 of file src/idake.c: 
msg IdakeEncryptedIdKeyMessage to send dumped as:
-----------------------------------------
(IdakeEncryptedRsIdKMessage 
 (encrsidkeymsg #41EA461344AD361317160803BE3E260DFE71DAC7EB1755BA98292940956C52E7B3378B918EE0F42BCB652E7FD80C8ADFA1D9549908C1F441F7A6DB7F5BB753BE390D6006ED4CB9471729CF5910AA5B53F97545FF557754206D898CB6DFCD3B7637B3A3ED31AA53CBC14525C15C247D3815CBFC867DDE205AD2EA07D9A191F2BC8C705B0CE12435DA20E9E51CEE2DE0B606A14D9E187FF5B1DE8025E125923F1F13D5779C47AC81E3B46875CFD09929C0CE3AF1B23455123FB1C29D47F048FB01949207177488C1C8F29C2DAC5EBB78BBFCA7477DC550C5952A3EECF7841FF7484F7DC74B3B2B15E4984655F1FB9D70A7#)
 )

-----------------------------------------

[AXC DEBUG] Function Idake_handle_ersigmsg, at line 1394 of file src/idake.c: 
msg IdakeMessage received dumped as:
-----------------------------------------
(IdakeMessage 
 (IdakeEncryptedRsigMessage 
  (encrsig #F1CA1A6FA12FB80574D8F520FBA2688760B98761E2ACA13724E82D4805477381D5DFF6EB1B37146F87DE56D1A633AD3B56829A7F8A53321DA40F30FD409772F8FE946ACA4AC86879C3C629AD6EAED7D3559D71647644CFE5FB1BD720B889056EE9C2BF795571FAD641E9E80A1E25F59AE78CB6596B5E85FEBEE0B40773EB7EDCB395A2C9EA03A79D624CDC08569A389CB86A6898F728EE698D671604B8E305D70B0B307EBE617E45C289F612A212F43BA47EA0102D34F5E243BA2517D8321ED6EC6CD9EEF277CFAE452CA01BFB7B0AFC#)
  )
 )

-----------------------------------------

[AXC ERROR] axc_pre_key_message_process_dake: not a pre key msg
[AXC INFO] Message from 1841412435@vault1: 
[AXC DEBUG] Function pre_key_odake_message_pre_deserialize, at line 842 of file src/odake.c: 
msg IdakeEncryptedIdKeyMessage received dumped as:
-----------------------------------------
(OdakePreKeyMessage 
 (prekey "1" #050600BA72A0D8193F66D30EAA3AC4022653BD31EB4E3BDFA71255438CD3F9BC5A#)
 (rspkid "0")
 (encidmsg #52879C676E810AB5DA6163635B13F2C1958893F9AA8124A36820D29F011F17E03F52DB2C60AF819494C472269E4031B551B2C5572F10EC3B53DF4C7BC35F5C0DB3ECCD3E2C71EFF074CF5EE553EBBD8D0291F1C5525A9E1A91A3B5FF2489CEC8ED7CFF0DB350AD430D348C315F8DE7D1FBC955D2674D5F099D95C8F8182FEB785F3C0E98E7C12DD8A7D394D51140719A1B26345644245B4921873D423C695672F5A483127C74CEABAFDC2C8AB8BF67FDE40E8FAEC7FAB2A347BF1C74D2D5B47320FC3544684339FC380262636F539BD9AFBCFB9E5DB3C08AAF3C4FFB6FA64AFB84D867165C9DC3D60BBE7FA3EE92878A013D49D5FA54A56EF28D97B46972ADC7B1F1E6BD939853E328612D1AA3C7B596#)
 (payload #330A2105793B577E3B37C038A229A6103C487F7915E00772B7A5BCA30F88665BBB5E27421000180022307DD0A54F0EAAF5C780C13707010BE7C02D37D9607523F4582BC8B7311684EE9D3E74D135E00356D963A254FC92218193893F8E145F9CE55F#)
 )

-----------------------------------------

[AXC DEBUG] Function pre_key_odake_message_post_deserialize, at line 978 of file src/odake.c: 
msg OdakeIdMessage decrypted dumped as:
-----------------------------------------
(OdakeIdMessage 
 (idkey #052ADFDC1FEB336806A12F1731829B8FD408E99AAE1B11E7E6E010A367160D4B73#)
 (regid "1841412435")
 (mac #B6FE8C37692C17CA566CCD3D64BA6530B4CE3A219BF98476EF34C3AC55BD70AE#)
 (rsig #CE65217895C34AFCFE3509E5A30C9E5F1DC5A413FB5FBCB2DA7AFB3F44AB4D01C92BD1615D56D3CB806711A435B9EAA0CAF506C85EAC6D516515FCCAF5FE560D39227B1700E84F62DFEE4259630E549B4D7DED9E12A625BDD4419031F1CE8309449E13A843157B862D34C21F26F186A6DED0083BC65F92B32DCBB9418D0DE20A683ABB4BF7E67F3CF2BFBDDD85EFF259B45A8339F41CCC5DBDAC13D79A5C4A0C4346C102DAA5978232FA0FE92275A65B621F01705158FC7ECB8ECC5AAB2CAF0B#)
 )

-----------------------------------------

[AXC INFO] A new session is created with the odake prekey msg correctly handled, and a prekey consumed, so update the bundle
[AXC DEBUG] axc_bundle_collect: entered
[AXC DEBUG] axc_bundle_collect: leaving
[AXC INFO] Message from 1841412435@vault1: Do you know the way to vault1317?
```

