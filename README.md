# CDJ_Clock
CDJ Clock is the missing link between Pioneers Pro DJ Link and Ableton Live. 

CDJ Clock generates MIDI beat clock from Pioneers Pro DJ Link. With CDJ Clock anything what understands MIDI Beat Clock can be synced to Pioneer CDJs.

Ableton Live can be tempo mastered from external sources. To sync external devices the preferred method is MIDI. One of the main functions of Pro DJ Link is BEAT SYNC between Pioneers CDJs by connecting the CDJs via Ethernet. The songs need to be analyzed with Recordbox to use this function. The beats then can be synced between the CDJs and DJM. It is not possible to natively connect to the Pro DJ Link, only the DJM (mixer) is sending out MIDI beat information’s on both the USB and the DIN connection.

The Problem: The DJM itself has a MIDI-Out function and sends MIDI beat clock signals but they were recalculated by build-in beat analyzing and will divert from the beat sync of the CDJs. Pressing the MIDI-Start/Stop button on the DJM will simple send out an MIDI Start or MIDI Stop signal when the button is pressed without any relation to the Pro DJ Link synchronization.

The Solution: Using CDJ Clock will recalculate the bpm based on the traffic information of the Pro DJ Link Ethernet connection between the CDJs and the DJM and continuously sends out a stable MIDI beat clock. This works between 60-180bpm. CDJ Clock will listen to MIDI commands. If a MIDI Start or MIDI Continue is received CDJ Clock waits for the next beat of Pro DJ Link and sends out the last MIDI Song Pointer and MIDI Continue. The MIDI Song Pointer can be moved in 4 or 32 beat steps.

Plese see videos:
https://www.youtube.com/watch?v=jXTiNU6RqOo
https://www.youtube.com/watch?v=iFwF3T2wz9I
