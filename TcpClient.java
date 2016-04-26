//bechin
import java.net.Socket;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.util.Random;

public class TcpClient{

	private static byte[] packet;
	private static byte[] code = new byte[4];

	public static void main(String[] args)throws IOException{
		try(Socket socket = new Socket("cs380.codebank.xyz", 38006)){
			InputStream in = socket.getInputStream();
			OutputStream out = socket.getOutputStream();
			packet = handshake1();
			//save mySeqNum
			int mySeqNum = 0;
			for(int i = 24; i < 28; i++){
				int thisByte = packet[i] & 0xFF;
				mySeqNum |= thisByte << (8*(27-i));
			}
			//printPacket();
			out.write(packet); //1st handshake
			//1st Handshake Response Code
			System.out.print("1st Handshake:\n");
			printCode(in);
			//READ TCP HEADER
			byte[] tcpResponse = new byte[20];
			in.read(tcpResponse);
			System.out.printf("mySeqNum: 0x%08X\n", mySeqNum);
			//printing and preparing to incr servSeqNum
			System.out.print("servSeqNum: 0x");
			int servSeqNum = 0;
			for(int i = 4; i < 8; i++){
				System.out.printf("%02X", tcpResponse[i]);
				int thisByte = tcpResponse[i] & 0xFF;
				servSeqNum |= thisByte << (8*(7-i));
			}
			System.out.printf("\nservSeqNum after assembling: 0x%08X\n\n", servSeqNum);
			//reformat 1st handshake into 2nd
			reformatHandshake2(++mySeqNum, ++servSeqNum);
			//printPacket();
			//write 2nd handshake
			out.write(packet);
			//2nd Handshake Response Code
			System.out.print("2nd Handshake:\n");
			printCode(in);
			for(int i = 1; i < 13; i++){
				int dataSize = (int)Math.pow(2.0, i);
				System.out.println("Packet size: 40 + " + dataSize);
				dataPacket(dataSize, mySeqNum + 1);
				mySeqNum += dataSize;
				out.write(packet);
				printCode(in);
			}
			teardown1(mySeqNum);
			out.write(packet);
			System.out.println("1st Teardown:");
			printCode(in);
			in.read(tcpResponse);
			in.read(tcpResponse);
			//NOT ANOTHER HANDSHAKE: ACTUALLY TEARDOWN 2
			System.out.println("IGNORE THE NEXT TWO LINES!!!");
			reformatHandshake2(0, 0);
			out.write(packet);
			System.out.println("2nd Teardown:");
			printCode(in);
		}
	}

	private static void teardown1(int mySeqNum){
		packet = new byte[40];
		packet[0] = 0b01000101; //version 4 and HLen 5
		packet[1] = 0; //TOS
		packet[2] = 0;  //first byte of length
		packet[3] = 40; //second byte of length
		packet[4] = 0; //first byte of Ident
		packet[5] = 0; //second byte of Ident
		packet[6] = (byte) 0x40; //flags and offset
		packet[7] = 0; //offset cont'd
		packet[8] = 50; //TTL
		packet[9] = 6; //protocol: TCP
		packet[10] = 0; //assume checksum 0 first
		packet[11] = 0; //assume checksum 0 first
		for(int j = 12; j < 16; j++) //all 0s for sourceAddr
			packet[j] = 0;
		packet[16] = 52;
		packet[17] = 33;
		packet[18] = (byte)131;
		packet[19] = 16;
		short checksum = checksum(packet, 20); //calc checksum
		packet[10] = (byte)(checksum >>> 8); //first byte of checksum
		packet[11] = (byte)checksum; //second byte of checksum
		//BEGIN TCP HEADER
		//all 0s for SrcPort and DstPort
		for(int i = 24; i < 28; i++) //mySeqNum
			packet[i] = (byte) (mySeqNum >>> (8*(27-i)));
		//all 0s for acknowledgement: packet[28 thru 31]
		packet[32] = 0b01010000; //HdrLen and 0s
		packet[33] = 1;
		byte[] psdoHdrTCP = makePsdoHdrTCP(packet, 32);
		checksum = checksum(psdoHdrTCP, 32);
		packet[36] = (byte) (checksum >> 8); //first byte of checksum
		packet[37] = (byte) checksum; //second byte of checksum
		//all 0s for UrgPtr
	}

	private static void dataPacket(int dataSize, int mySeqNum){
		int totalSize = 40 + dataSize;
		packet = new byte[totalSize];
		packet[0] = 0b01000101; //version 4 and HLen 5
		packet[1] = 0; //TOS
		packet[2] = (byte) (totalSize >>> 8);  //first byte of length
		packet[3] = (byte) totalSize; //second byte of length
		packet[4] = 0; //first byte of Ident
		packet[5] = 0; //second byte of Ident
		packet[6] = (byte) 0x40; //flags and offset
		packet[7] = 0; //offset cont'd
		packet[8] = 50; //TTL
		packet[9] = 6; //protocol: TCP
		packet[10] = 0; //assume checksum 0 first
		packet[11] = 0; //assume checksum 0 first
		for(int j = 12; j < 16; j++) //all 0s for sourceAddr
			packet[j] = 0;
		packet[16] = 52;
		packet[17] = 33;
		packet[18] = (byte)131;
		packet[19] = 16;
		short checksum = checksum(packet, 20); //calc checksum
		packet[10] = (byte)(checksum >>> 8); //first byte of checksum
		packet[11] = (byte)checksum; //second byte of checksum
		//BEGIN TCP HEADER
		//all 0s for SrcPort and DstPort
		for(int i = 24; i < 28; i++){
			packet[i] = (byte) (mySeqNum >>> (8*(27-i)));
		}
		//all 0s for acknowledgement: packet[28 thru 31]
		packet[32] = 0b01010000; //HdrLen and 0s
		//all 0s for FLAGS
		//all 0s for AdvertisedWindow
		byte[] randomData = new byte[dataSize];
		new Random().nextBytes(randomData);
		for(int i = 40; i < totalSize; i++)
			packet[i] = 0;//randomData[40-i];
		byte[] psdoHdrTCP = makePsdoHdrTCP(packet, 32+dataSize);
		checksum = checksum(psdoHdrTCP, 32+dataSize);
		packet[36] = (byte) (checksum >> 8); //first byte of checksum
		packet[37] = (byte) checksum; //second byte of checksum
	}

	private static void printCode(InputStream in)throws IOException{
		in.read(code);
		System.out.print("0x");
		for(byte e: code)
			System.out.printf("%02X", e);
		System.out.println("\n");
	}

	private static byte[] handshake1(){
		byte[] packet = new byte[40];
		packet[0] = 0b01000101; //version 4 and HLen 5
		packet[1] = 0; //TOS
		packet[2] = 0;  //first byte of length
		packet[3] = 40; //second byte of length
		packet[4] = 0; //first byte of Ident
		packet[5] = 0; //second byte of Ident
		packet[6] = (byte) 0x40; //flags and offset
		packet[7] = 0; //offset cont'd
		packet[8] = 50; //TTL
		packet[9] = 6; //protocol: TCP
		packet[10] = 0; //assume checksum 0 first
		packet[11] = 0; //assume checksum 0 first
		for(int j = 12; j < 16; j++) //all 0s for sourceAddr
			packet[j] = 0;
		packet[16] = 52;
		packet[17] = 33;
		packet[18] = (byte)131;
		packet[19] = 16;
		short checksum = checksum(packet, 20); //calc checksum
		packet[10] = (byte)(checksum >>> 8); //first byte of checksum
		packet[11] = (byte)checksum; //second byte of checksum
		//BEGIN TCP HEADER
		//all 0s for SrcPort and DstPort
		byte[] sequenceNum = new byte[4]; //seqNum
		new Random().nextBytes(sequenceNum); //randomizing
//		System.out.print("SequenceNumber: 0x");
//		for(byte b: sequenceNum)
//			System.out.printf("%02X", b);
//		System.out.println("\n");
		for(int j = 24; j < 28; j++) //inserting seqNum
			packet[j] = sequenceNum[j-24];
		//all 0s for acknowledgement: packet[28 thru 31]
		packet[32] = 0b01010000; //HdrLen and 0s
		packet[33] = 0b10; // SYN flag
		//all 0s for AdvertisedWindow
		byte[] psdoHdrTCP = makePsdoHdrTCP(packet, 32);
		checksum = checksum(psdoHdrTCP, 32);
		packet[36] = (byte) (checksum >> 8); //first byte of checksum
		packet[37] = (byte) checksum; //second byte of checksum
		//all 0s for UrgPtr
		return packet;
	}

	private static byte[] makePsdoHdrTCP(byte[] packet, int size){
		byte[] psdoHdrTCP = new byte[size];
		psdoHdrTCP[0] = 0; //protocol pad
		psdoHdrTCP[1] = 6; //protocol: TCP
		//skip psdoHdrTCP[2 thru 5] for sourceAddr
		for(int i = 6; i < 10; i++) //destAddr
			psdoHdrTCP[i] = packet[i+10];
		short length = (short)(size - 12);
		psdoHdrTCP[10] = (byte) (length >> 8); //first byte of length
		psdoHdrTCP[11] = (byte) length; //second byte of length
		for(int i = 12; i < size; i++){
			psdoHdrTCP[i] = packet[i+8];
		}
		return psdoHdrTCP;
	}

	//deprecated method for printing packets
	private static void printP(byte[] p){
		for(int i = 0; i < p.length; i+=4){
			int thisInt = p[i] & 0xFF;
			thisInt <<= 8;
			thisInt |= p[i+1] & 0xFF;
			thisInt <<= 8;
			thisInt |= p[i+2] & 0xFF;
			thisInt <<= 8;
			thisInt |= p[i+3] & 0xFF;
			System.out.printf("0x%08X\n", thisInt);
		}
	}

	private static short checksum(byte[] packet, int bound){
		long sum = 0;
		for(int i = 0; i < bound; i+=2){
			int thisInt = packet[i] & 0xFF;
			thisInt <<= 8;
			thisInt |= packet[i+1] & 0xFF;
			sum += thisInt;
			if((sum & 0xFFFF0000)!=0){
				sum &= 0x0000FFFF;
				sum++;
			}
		}
		return (short)~sum;
	}

	private static void reformatHandshake2(int mySeqNum, int seqNum){
		//seqNum is packet[24 thru 27]
		System.out.print("2nd Handshake seqNum: 0x");
		for(int i = 24; i < 28; i++){
			packet[i] = (byte) (mySeqNum >>> (8*(27-i)));
			System.out.printf("%02X", packet[i]);
		}
		System.out.println();
		System.out.print("2nd Handshake ackNum: 0x");
		for(int i = 28; i < 32; i++){
			packet[i] = (byte) (seqNum >>> (8*(31-i)));
			System.out.printf("%02X", packet[i]);
		}
		System.out.println("\n");
		//ACK flag
		packet[33] = 0b10000;
		//redo checksum
		//MUST RESET CHECKSUM BEFORE MAKING PsdoHdrTCP
		packet[36] = packet[37] = 0;
		byte[] psdoHdrTCP = makePsdoHdrTCP(packet, 32);
		short checksum = checksum(psdoHdrTCP, 32);
		packet[36] = (byte) (checksum >> 8); //first byte of checksum
		packet[37] = (byte) checksum; //second byte of checksum
	}

}
