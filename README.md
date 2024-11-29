# Xiaomi Protobuf Extractor

## Info
This utility is a tool for analyzing and decrypting packets used for communication with Xiaomi smart bands. Purpose of this utility is to assist in the development of Gadgetbridge. It uses Android BTSnoop log files to analyze packets transmitted between the smart band and the phone.

## Usage
1. Compile the protobuf file
```bash
protoc --python_out=. xiaomi.proto
```
2. Create and active virtual environment using venv
3. Install dependencies from requirements.txt
```bash
pip3 install -r requirements.txt
```
4. Run the extractor.py script using the command:
```bash
python3 extractor.py -k auth_key btsnoop_hci.log output.log
```
Where:
 - `auth_key` - the authentication key, which can be obtained by following the instructions from [Gadgetbridge Wiki](https://gadgetbridge.org/basics/pairing/huami-xiaomi-server/#mi-fitness-xiaomi-wear)
 - `btsnoop_hci.log` - the Android BTSnoop log file, which also can be obtained by followwing the instrctions from [Gadgetbridge Development Wiki](https://gadgetbridge.org/internals/development/bluetooth/#androids-bluetooth-logging)
 - `output.log` - the output file where the decrypted packets will be written

## Notes
 - Only XiaomiSppV2 supported for now
 - Tested only with Xiaomi Smart Band
 - xiaomi.proto was taken from [Gadgetbridge sources](https://codeberg.org/Freeyourgadget/Gadgetbridge/src/branch/master/app/src/main/proto/xiaomi.proto)