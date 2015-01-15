#!/bin/bash

make -C target_firmware
tar -cf ../firmware.tar ./target_firmware/htc_*.fw
if [ "$?" -eq 0 -a "$#" -le 0 ]; then
	echo -e "\nInstalling firmware images, this requires root privileges."
	sudo cp ./target_firmware/htc_7010.fw /lib/firmware/htc_7010.fw
	sudo cp ./target_firmware/htc_9271.fw /lib/firmware/htc_9271.fw
fi
