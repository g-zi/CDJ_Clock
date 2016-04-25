#define APP_NAME		"ProSync"
#define APP_DESC		"CDJ MIDI Clock"
#define APP_COPYRIGHT	"Copyright (c) 2016 Alex Godbehere & Georg Ziegler (DJ Yoi!)"
#define PACKETLIST_SIZE 32
#define SNAP_LEN 1518 // default snap length (maximum bytes per packet to capture)

#include <pcap.h>
#include <CoreMIDI/CoreMIDI.h>
#include <CoreFoundation/CoreFoundation.h>
#import <AudioToolbox/AudioToolbox.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <sys/time.h>
#include <signal.h>

extern int MIDIon;
int MIDIon = 0;
extern int MIDIchannelIn;
int MIDIchannelIn = 0;
extern int MIDIkeyStart;
int MIDIkeyStart = 0;
extern int MIDIkeyContinue;
int MIDIkeyContinue = 0;
extern int MIDIkeyStop;
int MIDIkeyStop = 0;

extern int SongPointerUp;
int SongPointerUp = 0;
extern int SongPointerDown;
int SongPointerDown = 0;

extern int SongPointerShiftUp;
int SongPointerShiftUp = 0;
extern int SongPointerShiftDown;
int SongPointerShiftDown = 0;

extern int MIDISource;
int MIDISource = 0;

extern int CDJSync;
int CDJSync = 0;


// Song Position Pointer = 0xF2, LSB, MSB
extern int SongPositionPointer;
int SongPositionPointer = 0; // highest 16383 1024.4.4 (~32min)

Byte midiClock[] = {0xF8};
Byte midiStart[] = {0xFA};
Byte midiContinue[] = {0xFB};
Byte midiStop[] = {0xFC};

MIDIClientRef   theMidiClient;
MIDIEndpointRef midiOut;
MIDIPortRef     outPort;

char pktBuffer[1024];
MIDIPacketList* pktList = (MIDIPacketList*) pktBuffer;
MIDIPacket     *pkt;


// MIDI_in start #########################################################

typedef struct MyMIDIPlayer { AUGraph graph; AudioUnit instrumentUnit; } MyMIDIPlayer;

void setupMIDI(MyMIDIPlayer *player);
void setupAUGraph(MyMIDIPlayer *player);
static void	MyMIDIReadProc(const MIDIPacketList *pktlist, void *refCon, void *connRefCon);
void MyMIDINotifyProc (const MIDINotification  *message, void *refCon);

static void SongPositionOut() {
    Byte SPP_LSB = 0b01111111 & SongPositionPointer * 4;
    Byte SPP_MSB = 0b01111111 & SongPositionPointer * 4 >> 7;
    Byte SongPosition[] = {0xF2, SPP_LSB, SPP_MSB};
    pkt = MIDIPacketListInit(pktList);
    pkt = MIDIPacketListAdd(pktList, PACKETLIST_SIZE, pkt, 0, 3, SongPosition);
    MIDIReceived(midiOut, pktList);  // Send MIDI data
    printf("Song Position Pointer = %d \n", SongPositionPointer);}


static void CheckError(OSStatus error, const char *operation) {
    if (error == noErr) return;
    char str[20];
    *(UInt32 *)(str + 1) = CFSwapInt32HostToBig(error);
    if (isprint(str[1]) && isprint(str[2]) && isprint(str[3]) && isprint(str[4]))
    { str[0] = str[5] = '\''; str[6] = '\0'; }
    else sprintf(str, "%d", (int)error);
    fprintf(stderr, "Error: %s (%s)\n", operation, str);
    exit(1); }


static void	MyMIDIReadProc(const MIDIPacketList *pktlist, void *refCon, void *connRefCon) {
    MIDIPacket *packet = (MIDIPacket *)pktlist->packet;
    for (int i=0; i < pktlist->numPackets; i++) {
        Byte midiStatus = packet->data[0];
        Byte midiChannel = (0x0F & midiStatus)+1;
        Byte midiCommand = midiStatus >> 4;
        Byte data1 = packet->data[1];
        Byte data2 = packet->data[2];

/*/ midi to audio
    MyMIDIPlayer *player = (MyMIDIPlayer*) refCon;
    CheckError(MusicDeviceMIDIEvent (player->instrumentUnit, midiStatus, data1, data2, 0),
               "Couldn't send MIDI event");
*/
        if (midiStatus == *midiStart) { MIDIon = 1; } // MIDIstart 0xFA
        if (midiStatus == *midiStop)  { MIDIon = 0; } // MIDIstop  0xFC

        // note-on/off
        if ((midiCommand == 0x08) || (midiCommand == 0x09))
        {
            // number |= 1 << x; // set bit
            // number &= ~(1 << x); // clear bit
            // number ^= 1 << x; // toggle bit
            // bit = number & (1 << x); // check bit
            
            if (data1==MIDIkeyContinue && midiChannel==MIDIchannelIn && data2==127) {
                if (MIDIkeyStop==0 && MIDIon ==1) {MIDIon = 0;} else {MIDIon = 1;}}
            
            if (data1==MIDIkeyStop && midiChannel==MIDIchannelIn && data2==127) {
                if (MIDIon==2) {SongPositionPointer=0; SongPositionOut(); } MIDIon = 0; }

            // jump 4/4 beat back (1 bar)
            if (data1==SongPointerUp && midiChannel==MIDIchannelIn && data2==127) {
                if(SongPositionPointer == (SongPositionPointer & ~(0b10))) {
                    SongPositionPointer = SongPositionPointer - 4;}
                SongPositionPointer &= ~(0b11); // clear bits
                SongPositionOut();}

            // jump to next 4/4 beat (1 bar)
            if (data1==SongPointerDown && midiChannel==MIDIchannelIn && data2==127) {
                SongPositionPointer &= ~(0b11); // clear bits
                SongPositionPointer = SongPositionPointer + 4;
                SongPositionOut();}
            
            // jump 8 bar back (32 beat)
            if (data1==SongPointerShiftUp && midiChannel==MIDIchannelIn && data2==127) {
                if(SongPositionPointer == (SongPositionPointer & ~(0b11110))) {
                    SongPositionPointer = SongPositionPointer - 32;}
                SongPositionPointer &= ~(0b11111); // clear bits
                SongPositionOut();}

            // jump to next 8 bar (32 beat)
            if (data1==SongPointerShiftDown && midiChannel==MIDIchannelIn && data2==127) {
                SongPositionPointer &= ~(0b11111); // clear bits
                SongPositionPointer = SongPositionPointer + 32;
                SongPositionOut();}
            
            if(midiCommand == 0x08) {
                printf("Channel=%d  NoteOff=%d  Velocity=%d \n", midiChannel, data1, data2);}

            if(midiCommand == 0x09) {
                printf("Channel=%d  NoteOn=%d  Velocity=%d \n", midiChannel, data1, data2);}
            
            // TEST
/*
                  // F0 7F cc 01 01 hr mn sc fr F7
                 Byte TC_Hour = 0;
                 Byte TC_Min = 10;
                 Byte TC_Sec = 1;
                 Byte TC_Frame = 1;
                 Byte TimeCode[] = {0xF0, 0x7F, 0x7F, 0x01, 0x01, TC_Hour, TC_Min, TC_Sec, TC_Frame, 0x7F};
                 pkt = MIDIPacketListInit(pktList);
                 pkt = MIDIPacketListAdd(pktList, PACKETLIST_SIZE, pkt, 0, 10, TimeCode);
                 MIDIReceived(midiOut, pktList);  // Send MIDI data
*/
            // TEST
        }
        else if (midiCommand > 0x09)
        {
            if(midiCommand == 0x0A) {
                printf("Channel=%d  Polyphonic=%d  Pressure=%d \n",
                       midiChannel, data1, data2);}
            
            if(midiCommand == 0x0B) {
                printf("Channel=%d  Control=%d  Data=%d \n",
                       midiChannel, data1, data2);}
            
            if(midiCommand == 0x0C) {
                printf("Channel=%d  Program=%d \n",
                       midiChannel, data1);}
            
            if(midiCommand == 0x0D) {
                printf("Channel=%d  Aftertouch=%d \n",
                       midiChannel, data1);}
            
            if(midiCommand == 0x0E) {
                printf("Channel=%d  PitchWheel  LSbyte=%d  MSbyte=%d \n",
                       midiChannel, data1, data2);}
        }
        else
        {
            printf("Channel=%d  midiCommand=%d  Byte1=%d  Byte2=%d \n",
                   midiChannel, midiCommand, data1, data2);
        }
        packet = MIDIPacketNext(packet);
    }
}

void MyMIDINotifyProc (const MIDINotification  *message, void *refCon)
{    printf("MIDI Notify, messageId=%d,", message->messageID); }

void setupAUGraph(MyMIDIPlayer *player)
{
    CheckError(NewAUGraph(&player->graph), "Couldn't open AU Graph");
    
    AudioComponentDescription outputcd = {0};
    outputcd.componentType = kAudioUnitType_Output;
    outputcd.componentSubType = kAudioUnitSubType_DefaultOutput;
    outputcd.componentManufacturer = kAudioUnitManufacturer_Apple;
    
    AUNode outputNode;
    CheckError(AUGraphAddNode(player->graph, &outputcd, &outputNode),
               "AUGraphAddNode[kAudioUnitSubType_DefaultOutput] failed");
    
    AudioComponentDescription instrumentcd = {0};
    instrumentcd.componentManufacturer = kAudioUnitManufacturer_Apple;
    instrumentcd.componentType = kAudioUnitType_MusicDevice;
    instrumentcd.componentSubType = kAudioUnitSubType_DLSSynth;
    
    AUNode instrumentNode;
    CheckError(AUGraphAddNode(player->graph, &instrumentcd, &instrumentNode),
               "AUGraphAddNode[kAudioUnitSubType_DLSSynth] failed");
    
    CheckError(AUGraphOpen(player->graph),
               "AUGraphOpen failed");
    
    CheckError(AUGraphNodeInfo(player->graph, instrumentNode, NULL, &player->instrumentUnit),
               "AUGraphNodeInfo failed");
    
    CheckError(AUGraphConnectNodeInput(player->graph, instrumentNode, 0, outputNode, 0),
               "AUGraphConnectNodeInput");
    
    CheckError(AUGraphInitialize(player->graph),
               "AUGraphInitialize failed");
}

void setupMIDI(MyMIDIPlayer *player)
{
    MIDIClientRef client;
    CheckError (MIDIClientCreate(CFSTR("Core MIDI to System Sound"), MyMIDINotifyProc, player, &client),
                "Couldn't create MIDI client");
    
    MIDIPortRef inPort;
    CheckError (MIDIInputPortCreate(client, CFSTR("Input port"), MyMIDIReadProc, player, &inPort),
                "Couldn't create MIDI input port");
    
    unsigned long sourceCount = MIDIGetNumberOfSources();
    printf ("%ld sources\n", sourceCount);
    for (int i = 0; i < sourceCount; ++i) {
        MIDIEndpointRef src = MIDIGetSource(i);
        CFStringRef endpointName = NULL;
        CheckError(MIDIObjectGetStringProperty(src, kMIDIPropertyName, &endpointName),
                    "Couldn't get endpoint name");
        char endpointNameC[255];
        CFStringGetCString(endpointName, endpointNameC, 255, kCFStringEncodingUTF8);
        printf("  source %d: %s ", i, endpointNameC);

        // connects to source
        if (
            i>=0 || //connects everything
            strncmp(endpointNameC, "Teensy MIDI",11)==0 ||
            strncmp(endpointNameC, "SLIDER/KNOB",11)==0 || // NanoControl
            strncmp(endpointNameC, "User Port",8)==0 || // Ableton Push user mode
            strncmp(endpointNameC, "DJM-2000",8)==0 ||
            strncmp(endpointNameC, "DJM-900",7)==0
            ) {
            CheckError (MIDIPortConnectSource(inPort, src, NULL), "Couldn't connect MIDI port");
            printf("<-- connected ");}

        printf("\n");
    }
}

// MIDI_in end #########################################################


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
double calculatedBPM, CDJtime, lastCDJtime, MIDItime;

int cdjstart = 0;
int nocount = 0;
double lastBPM = 0;
double BPMdiff, CDJdiff, lastCDJdiff = 0;

void MIDItimer(void);
struct itimerval it_val;    // for itimer
int clockcounter = 0;
double tickcounts = 19.2; // 20 = 122pbm, 19 = 130bpm

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    switch(packet[75]) // CDJ 1-4 ?
    {
        // sync on DJM = case 33 .. break; if sync on CDJs = case 1-4 .. break
        case 0 : //cdj = packet[89]; // cdj master??
        case 1 : nocount = 0; if(cdjstart==0) {cdjstart = 1;} if(CDJSync==1 || CDJSync==9) {break;} else {return;}
        case 2 : nocount = 0; if(cdjstart==0) {cdjstart = 1;} if(CDJSync==2 || CDJSync==9) {break;} else {return;}
        case 3 : nocount = 0; if(cdjstart==0) {cdjstart = 1;} if(CDJSync==3 || CDJSync==9) {break;} else {return;}
        case 4 : nocount = 0; if(cdjstart==0) {cdjstart = 1;} if(CDJSync==4 || CDJSync==9) {break;} else {return;}
        case 33 : if(packet[74]==0 && CDJSync==0) {break;} else {return;} // sync on DJM2000
        default : return; // not a packet from CDJ 1-4
    }
    
    CDJtime = header->ts.tv_sec * 1000 + header->ts.tv_usec * 0.001;
    CDJdiff = (CDJtime-(CDJtime-lastCDJtime)/2-MIDItime); // compare to half beat
    
    tickcounts = (CDJtime-lastCDJtime)/24+CDJdiff/48; // 48
    if (tickcounts < 10) {tickcounts=10;} // avoid timer is stopping
    if (tickcounts > 50) {tickcounts=50;} // avoid timer is stopping
    
    calculatedBPM = 60000 / (CDJtime - lastCDJtime);
    if(calculatedBPM > 200) {return;} // ignore invalid PBM
    lastCDJtime = CDJtime;
    BPMdiff = calculatedBPM - lastBPM;

    printf("noBeat=%d, BPM:%f  Tick:%f  CDJdiff:%f  BPMdiff:%f \n", nocount, calculatedBPM, tickcounts, CDJdiff, BPMdiff);
    
    lastBPM = calculatedBPM;
    if(BPMdiff > 20 || BPMdiff < -20) {return;}
    
    if(cdjstart == 1 && MIDIon == 1) // start MIDI
    {
        Byte SPP_LSB = 0b01111111 & SongPositionPointer*4;
        Byte SPP_MSB = 0b01111111 & SongPositionPointer*4 >> 7;
        Byte SongPosition[] = {0xF2, SPP_LSB, SPP_MSB};
        pkt = MIDIPacketListInit(pktList);
        pkt = MIDIPacketListAdd(pktList, PACKETLIST_SIZE, pkt, 0, 3, SongPosition);
        MIDIReceived(midiOut, pktList);  // Send MIDI data

        pkt = MIDIPacketListInit(pktList);
        pkt = MIDIPacketListAdd(pktList, PACKETLIST_SIZE, pkt, 0, 1, midiContinue); // midiContinue  midiStart
        MIDIReceived(midiOut, pktList); // Send MIDI Start
        cdjstart = 2;
        printf("MIDI-Clock START\n");
        return;
    }

    nocount++;
    if((nocount > 70 || MIDIon == 0)) // stop midi if no CDJ is sending
    {
        pkt = MIDIPacketListInit(pktList);
        pkt = MIDIPacketListAdd(pktList, PACKETLIST_SIZE, pkt, 0, 1, midiStop);
        MIDIReceived(midiOut, pktList); // Send MIDI Stop
        printf("MIDI-Clock STOP\n");
        SongPositionPointer &= ~(0b11); // clear bits (set to last 4/4 beat)
        SongPositionOut();
        nocount = 0;
        cdjstart = 0;
        MIDIon = 2;
        return;
    }
    return;
}

void MIDItimer(void)
{
    it_val.it_value.tv_sec = tickcounts/1000;
    it_val.it_value.tv_usec = tickcounts*1000;
    it_val.it_interval = it_val.it_value;
    if (setitimer(ITIMER_REAL, &it_val, NULL) == -1) {} // set new time for itimer
    
    if (clockcounter > 23)
    {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        MIDItime = tv.tv_sec * 1000 + tv.tv_usec * 0.001;
        clockcounter = 0;
        if(cdjstart == 2 && MIDIon == 1) {SongPositionPointer++;}
//            printf ("cdjstart=%d   MIDIon=%d   SongPositionPointer=%d   MIDIShift=%d \n", cdjstart, MIDIon, SongPositionPointer, MIDIShift);
    }
    clockcounter++;
    
    pkt = MIDIPacketListInit(pktList);
    pkt = MIDIPacketListAdd(pktList, PACKETLIST_SIZE, pkt, 0, 1, midiClock);
    MIDIReceived(midiOut, pktList); // Send Tap Tempo MIDI
}

void move_pthread_to_realtime_scheduling_class(pthread_t pthread)
{
    mach_timebase_info_data_t timebase_info;
    mach_timebase_info(&timebase_info);
    
    const uint64_t NANOS_PER_MSEC = 1000000ULL;
    double clock2abs = ((double)timebase_info.denom / (double)timebase_info.numer) * NANOS_PER_MSEC;
    
    thread_time_constraint_policy_data_t policy;
    policy.period      = 0;
    policy.computation = (uint32_t)(5 * clock2abs); // 5 ms of work
    policy.constraint  = (uint32_t)(10 * clock2abs);
    policy.preemptible = FALSE;
    
    int kr = thread_policy_set(pthread_mach_thread_np(pthread_self()),
                               THREAD_TIME_CONSTRAINT_POLICY,
                               (thread_policy_t)&policy,
                               THREAD_TIME_CONSTRAINT_POLICY_COUNT);
    if (kr != KERN_SUCCESS) {
        mach_error("thread_policy_set:", kr);
        exit(1);
    }
}

int main(int argc, char **argv)
{
    printf("CDJ MIDI Clock (c) Alex Godbehere & Georg Ziegler (DJ Yoi!)\n");
    printf("Virtual MIDI Clock from Pioneer CDJs via Ethernet connection\n\n");
    printf("Parameter: CDJ_Clock Ethernet MIDI-Channel MIDI-Start MIDI-Stop SP-Up SP-Down syncCDJ \n");
    printf("           CDJ_Clock en0 16 117 118 115 116 127 CDJ1 (en3 for MacBook Retina)\n\n");
    
    // MIDI_in
    MyMIDIPlayer player;
    setupAUGraph(&player);
    setupMIDI(&player);
    CheckError (AUGraphStart(player.graph), "couldn't start graph");
    
    MIDIClientCreate(CFSTR("Magical MIDI"), NULL, NULL, &theMidiClient);
    MIDISourceCreate(theMidiClient, CFSTR("ProSync"), &midiOut);
    
    char *dev = NULL;                   // capture device name
    char errbuf[PCAP_ERRBUF_SIZE];      // error buffer
    pcap_t *handle;                     // packet capture handle
    char filter_exp[] = "port 50001";	// filter expression
    struct bpf_program fp;              // compiled filter program
    bpf_u_int32 mask;                   // subnet mask
    bpf_u_int32 net;                    // ip
    int num_packets = 0;                // number of capture packets
    
    lastCDJtime = 0;
    CDJtime= 0;
    
    // check for command line options
    for (int i=1; i<argc; i++) {
        if (atoi(argv[i]) != 0) {
            MIDIchannelIn = atoi(argv[i]);
            if ((i+1 < argc)) { if (atoi(argv[i+1]) != 0) { MIDIkeyContinue = atoi(argv[i+1]); }}
            if ((i+2 < argc)) { if (atoi(argv[i+2]) != 0) { MIDIkeyStop = atoi(argv[i+2]); }}
            if ((i+3 < argc)) { if (atoi(argv[i+3]) != 0) { SongPointerUp = atoi(argv[i+3]); }}
            if ((i+4 < argc)) { if (atoi(argv[i+4]) != 0) { SongPointerDown = atoi(argv[i+4]); }}
            if ((i+5 < argc)) { if (atoi(argv[i+5]) != 0) { SongPointerShiftUp = atoi(argv[i+5]); }}
            if ((i+6 < argc)) { if (atoi(argv[i+5]) != 0) { SongPointerShiftDown = atoi(argv[i+6]); }}
            break; }}

    // en Channel Continue Stop Up Down ShiftUp ShiftDonw CDJ
    // en ch C S U D shU shD CDJ
    
    for (int i=1; i<argc; i++) {
        if (strstr(argv[i],"CDJ") != NULL) {
            CDJSync = atoi(strncpy(argv[i],argv[i]+3,1));
            if (CDJSync==0) {CDJSync = 9; }}
        
        if (strstr(argv[i],"en") != NULL) {
            dev = argv[i]; }}

    // find a capture device if not specified on command-line
    if (dev == NULL) {
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n",errbuf);
            exit(EXIT_FAILURE); }}
    
    // get capture device network number and mask
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",dev, errbuf);
        net = 0; mask = 0;}
    
    printf("Capture Device: %s   Filter: %s",dev, filter_exp);
    if(CDJSync==9) { printf("   Sync: CDJ 1-4"); }
    else if(CDJSync!=0) { printf("   Sync: CDJ%d",CDJSync); }
    else { printf("   Sync: DJM"); }
    printf("\n");
    
    if(MIDIchannelIn!=0) { printf("MIDI Sync Start/Stop: Channel=%d",MIDIchannelIn); }
    if(MIDIkeyContinue!=0) { printf(" Start=%d",MIDIkeyContinue); }
    if(MIDIkeyStop!=0) { printf(" Stop=%d",MIDIkeyStop); }
    if(SongPointerUp!=0) { printf(" Up=%d",SongPointerUp); }
    if(SongPointerDown!=0) { printf(" Down=%d",SongPointerDown); }
    if(SongPointerShiftUp!=0) { printf(" ShiftUp=%d",SongPointerShiftUp); }
    if(SongPointerShiftDown!=0) { printf(" ShiftDown=%d",SongPointerShiftDown); }
    if(MIDIchannelIn!=0 || MIDIkeyContinue!=0 || MIDIkeyStop!=0) {printf("\n"); }
    printf("\n");
    
    // open capture device
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);}
    else {
        int fd; fd = pcap_fileno(handle);
        if (fd == -1) {
            fprintf(stderr, "Can't get file descriptor for pcap_t (this should not happen)\n");
            return 2; }
        if (set_immediate_mode(fd) == -1) {
            fprintf(stderr, "BIOCIMMEDIATE failed: %s\n", strerror(errno));
            return 2;}}
    
    // Ethernet device capture
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);}
    
    // filter expression
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);}
    
    // set filter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);}
    
    // SIGALRM calls MIDItimer()
    if (signal(SIGALRM, (void (*)(int)) MIDItimer) == SIG_ERR) {}
    it_val.it_value.tv_sec = tickcounts/1000;
    it_val.it_value.tv_usec = tickcounts*1000;
    it_val.it_interval = it_val.it_value;
    if (setitimer(ITIMER_REAL, &it_val, NULL) == -1) {}
    move_pthread_to_realtime_scheduling_class(ITIMER_REAL);
    
    pthread_t loopThread;
    int iret;
    
    // set callback function
    iret = pthread_create(&loopThread, NULL, pcap_loop(handle, num_packets, got_packet, NULL), NULL);
    
    // cleanup and close session
    pcap_freecode(&fp); pcap_close(handle);
    
    return 0;
}