using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SSLServer
{
    class SSLServer
    {
        #region static variables
        /// <summary>
        /// certificate
        /// </summary>
        public static X509Certificate2 serverCertificate;

        /// <summary>
        /// the crypto provider
        /// </summary>
        public static RSACryptoServiceProvider serverRSA;

        /// <summary>
        /// delimeter for messages
        /// </summary>
        public static string delimeter = "748159263";

        /// <summary>
        /// nonces
        /// </summary>
        public static string serverNonce;
        public static string clientNonce;

        /// <summary>
        /// the total messages so far
        /// </summary>
        public static byte[] totalMessages = new byte[0];

        /// <summary>
        /// necessary keysto be computed
        /// </summary>
        public static string chosenSecret;
        public static byte[] K;
        public static byte[] IntegrityProtectionKeyCient;
        public static byte[] IntegrityProtectionKeyServer;
        public static byte[] EncryptionKeyCient;
        public static byte[] EncryptionKeyServer;

        #endregion

        #region main method
        static void Main(string[] args)
        {
            generateRandoms(16);

            // start by attempting to load our certificate
            if(!LoadCertificate("testCertificate"))
            {
                Console.WriteLine("load cert failed.");
                return;
            }

            // these methods are just tog et the server listening for the appropriate
            // amount of messages. message handling is done in its own method below.
            string clientNonce = StartListening(11000);
            string message2 = StartListening(11001);
            string message3 = StartListening(11002);

            Console.WriteLine("");
            Console.WriteLine("DONE");
            Console.WriteLine("Press Enter To Terminate");
            Console.Read();
        }

        public static string pp(string toPrint)
        {
            return BitConverter.ToString(getBytes(toPrint));
        }

        public static string pp(byte[] toPrint)
        {
            return BitConverter.ToString(toPrint);
        }

        #endregion

        #region socket sending
        /// <summary>
        /// performs the socket communication. sends one message, recieves one message.
        /// </summary>
        /// <param name="toSend"></param>
        /// <returns></returns>
        public static string StartListening(int port)
        {
            string data = null;
         
            // Data buffer for incoming data.
            byte[] bytes = new Byte[1024];
            IPAddress addr = IPAddress.Loopback;
            //socket stuff
            IPEndPoint localEndPoint = new IPEndPoint(addr, port);
            // Create a TCP/IP socket.
            Socket listener = new Socket(AddressFamily.InterNetwork,
                SocketType.Stream, ProtocolType.Tcp);

            // Bind the socket to the local endpoint and 
            // listen for incoming connections.
            try
            {
                listener.Bind(localEndPoint);
                listener.Listen(10);

                // Program is suspended while waiting for an incoming connection.
                Socket handler = listener.Accept();
                data = null;

                // An incoming connection needs to be processed.
                while (true)
                {
                    bytes = new byte[1024];
                    int bytesRec = handler.Receive(bytes);
                    //data += Encoding.ASCII.GetString(bytes, 0, bytesRec);
                    data += getString(bytes);
                    if (data.IndexOf("<EOF>") > -1)
                    {
                        data = data.Substring(0, data.IndexOf("<EOF>"));
                        break;
                    }
                }

                byte[] toSend;
                if(!handleMessage(data, out toSend))
                {
                    Console.WriteLine("message could not be hanndled: " + data);
                    return null;
                }

                handler.Send(combineBytes(toSend, getBytes("<EOF>")));
                handler.Shutdown(SocketShutdown.Both);
                handler.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }

            return data;
        }
        #endregion

        #region message handling
        /// <summary>
        /// switch on message type and handle it appropriately
        /// </summary>
        /// <param name="message"></param>
        /// <param name="response"></param>
        /// <returns></returns>
        public static bool handleMessage(string message, out byte[] response)
        {
            bool toReturn = false;
            var splitMessage = message.Split(new string[]{delimeter}, StringSplitOptions.None);
            var messageType = splitMessage[0];

            switch(messageType)
            {
                case "nonce":
                    Console.WriteLine("1. Server recieves nonce from client\nNonce>\t" + pp(splitMessage[1]) + "\n");
                    response = combineBytes(getCertificate(), getBytes(delimeter));
                    response = combineBytes(response, getBytes(serverNonce));
                    Console.WriteLine("2. Server sends certificate and nonce in reply to client\nserverNonce>\t" + pp(serverNonce + "\n"));
                    totalMessages = combineBytes(totalMessages, getBytes(splitMessage[1]));
                    totalMessages = combineBytes(totalMessages, getCertificate());
                    totalMessages = combineBytes(totalMessages, getBytes(serverNonce));
                    clientNonce = splitMessage[1];
                    toReturn = true;
                    break;

                case "secret":
                    Console.WriteLine("3. Server recieves encrypted secret from client");
                    Console.WriteLine("4. Server decrypts secret using private key");
                    chosenSecret = rsaDecrypt(splitMessage[1]);
                    Console.WriteLine("5. Server calculates all needed keys from decrypted secret key\ndecryptedSecret>\t" + pp(chosenSecret) + "\n");
                    computeSecretKeys();
                    totalMessages = combineBytes(totalMessages, getBytes(splitMessage[1]));
                    Console.WriteLine("6. Server computes hash of all messages and sends to client\nhash>\t" + pp(getHashOfMessage(totalMessages, "server")) + "\n");
                    response = getHashOfMessage(totalMessages, "server");
                    toReturn = true;
                    break;

                case "hash":
                    Console.WriteLine("7. Server recieves hash of all messages from client\nhash>\t" + pp(splitMessage[1]) + "\n");
                    Console.WriteLine("8. Server attempts to verify the has of all messages from client");
                    if(splitMessage[1] != getString(getHashOfMessage(totalMessages, "client")))
                    {
                        Console.WriteLine("hash of messages from client does not match our own!");
                        response = null;
                        return false;
                    }
                    Console.WriteLine("9. Hash verification has PASSED");
                    Console.WriteLine("10. Server responds with the ssl formated data message of a 50k file");
                    response = getDataMessage();
                    toReturn = true;
                    break;

                default:
                    response = null;
                    break;
            }

            return toReturn;
        }
        #endregion

        #region data message and file

        /// <summary>
        /// get the data message of the hashed encrypted file
        /// </summary>
        /// <returns></returns>
        public static byte[] getDataMessage()
        {
            // formats for the different portions of the message
            string dataMessageFormat = "{0}{1}{2}{3}{4}";
            string encryptedPortionFormat = "{0}{1}{2}";
            string hashedPortionFormat = "{0}{1}{2}{3}{4}";

            // sequence number
            string sequence = "1";
            Console.WriteLine("sequence>\t" + pp(sequence));

            // record header
            string recordHeader = "data-v3-9";
            Console.WriteLine("recordHeader>\t" + pp(recordHeader));

            // text of the file
            string dataFile = loadFile();

            // combine sequence, RH, dataFile and hash them
            string hashedPortion = getString(getHashOfMessage(
                getBytes(String.Format(hashedPortionFormat, sequence, delimeter, recordHeader, delimeter, dataFile)),
                getString(IntegrityProtectionKeyServer)));

            Console.WriteLine("hashedPortion>\t" + pp(hashedPortion)+"\n");

            // encrypt dataFile, hashValue
            string encryptedPortion = getString(encryptMessage( EncryptionKeyServer,
                getBytes(String.Format(encryptedPortionFormat, dataFile, delimeter, hashedPortion))));

            // combine sequence, RH, encrypted message
            string totalMessage = String.Format(dataMessageFormat, sequence,
                delimeter, recordHeader, delimeter, encryptedPortion);

            // return the message in byte form
            return getBytes(totalMessage);
        }

        /// <summary>
        /// load the testFile into a string
        /// </summary>
        /// <returns></returns>
        public static string loadFile()
        {
            return File.ReadAllText("testFile.txt");
        }

        /// <summary>
        /// loads an ssl certificate into our global x509 certificate value
        /// </summary>
        /// <param name="certName">name of the file where the cert is stored</param>
        /// <returns></returns>
        public static bool LoadCertificate(string certName)
        {
            try
            {
                serverCertificate = new X509Certificate2("TaylorStapletonCertificate.pfx");
                
                serverRSA = (RSACryptoServiceProvider)serverCertificate.PrivateKey;

                return true;
            }
            catch(Exception e)
            {
                Console.WriteLine(e.Message);
                return false;
            }
        }
        #endregion

        #region encryption and hashing

        /// <summary>
        /// generate the serverNonce
        /// </summary>
        /// <param name="numberOfNonceBytes"></param>
        public static void generateRandoms(int numberOfNonceBytes)
        {
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            byte[] randomNonceBytes = new byte[numberOfNonceBytes];

            rngCsp.GetNonZeroBytes(randomNonceBytes);
            
            serverNonce = getString(randomNonceBytes);
        }

        /// <summary>
        /// triple des encryptor method
        /// </summary>
        /// <param name="key"></param>
        /// <param name="message"></param>
        /// <returns></returns>
        public static byte[] encryptMessage(byte[] key, byte[] message)
        {
            byte[] keyBytes = key;
            byte[] messageBytes = message;
            byte[] ivBytes = new byte[] { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7 };

            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            tdes.Key = keyBytes;
            tdes.IV = ivBytes;
            tdes.Mode = CipherMode.CBC;
            tdes.Padding = PaddingMode.PKCS7;

            ICryptoTransform encryptor = tdes.CreateEncryptor();

            byte[] encResult = encryptor.TransformFinalBlock(messageBytes, 0, messageBytes.Length);

            tdes.Clear();

            return encResult;
        }

        /// <summary>
        /// get the byte representation of our ssl certificate
        /// </summary>
        /// <returns>certificate in byte form</returns>
        public static byte[] getCertificate()
        {
            //return serverCertificate.GetRawCertData();
            return getBytes(serverCertificate.PublicKey.Key.ToXmlString(false));
        }

        /// <summary>
        /// use our rsa instance to decrypt a string of ciphertext
        /// </summary>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public static string rsaDecrypt(string cipherText)
        {
            //get our bytes
            byte[] bytesCipherText = getBytes(cipherText);

            //decrypt and strip pkcs#1.5 padding
            var bytesPlainTextData = serverRSA.Decrypt(bytesCipherText, false);

            //get our original plainText back...
            var plainTextData = getString(bytesPlainTextData);

            return plainTextData;
        }

        /// <summary>
        /// get the hash value of all messages so far
        /// </summary>
        /// <returns></returns>
        public static byte[] getHashOfMessage(byte[] totalMessages, string appendage)
        {
            MD5 md5 = System.Security.Cryptography.MD5.Create();
            byte[] inputBytes = combineBytes(K, totalMessages);
            inputBytes = combineBytes(inputBytes, getBytes(appendage));
            byte[] hash = md5.ComputeHash(inputBytes);
            return md5.ComputeHash(inputBytes);
        }

        #endregion

        #region key calculation
        /// <summary>
        /// computes both the incoming and outgoing keys
        /// </summary>
        public static void computeSecretKeys()
        {
            K = xorBytes(getBytes(serverNonce), xorBytes(getBytes(clientNonce), getBytes(chosenSecret)));

            IntegrityProtectionKeyCient = transform(K, -1);
            IntegrityProtectionKeyServer = transform(K, 1);
            EncryptionKeyCient = transform(K, -2);
            EncryptionKeyServer = transform(K, 2);

            Console.WriteLine("K>\t" + pp(K));
            Console.WriteLine("IPKeyClient>\t" + pp(IntegrityProtectionKeyCient));
            Console.WriteLine("IPKeyServer>\t" + pp(IntegrityProtectionKeyServer));
            Console.WriteLine("EncryptionKeyClient>\t" + pp(EncryptionKeyCient));
            Console.WriteLine("EncryptionKeyServer>\t" + pp(EncryptionKeyServer));
        }
        #endregion

        #region string byte methods
        /// <summary>
        /// xor two byte arrays together
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        public static byte[] xorBytes(byte[] a, byte[] b)
        {
            byte[] toReturn = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
            {
                toReturn[i] = (byte)(a[i] ^ b[i]);
            }
            return toReturn;
        }

        /// <summary>
        /// get a string from byte[]
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static string getString(byte[] bytes)
        {
            char[] chars = new char[bytes.Length / sizeof(char)];
            System.Buffer.BlockCopy(bytes, 0, chars, 0, bytes.Length);
            return new string(chars);
        }

        /// <summary>
        /// get bytes from a string
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static byte[] getBytes(string str)
        {
            byte[] bytes = new byte[str.Length * sizeof(char)];
            System.Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        /// <summary>
        /// combine two byte []'s
        /// </summary>
        /// <param name="a1"></param>
        /// <param name="a2"></param>
        /// <returns></returns>
        public static byte[] combineBytes(byte[] a1, byte[] a2)
        {
            byte[] rv = new byte[ a1.Length + a2.Length];
            System.Buffer.BlockCopy( a1, 0, rv, 0, a1.Length );
            System.Buffer.BlockCopy( a2, 0, rv, a1.Length, a2.Length );
            return rv;
        }

        /// <summary>
        /// transform the given byte array by the given value
        /// </summary>
        /// <param name="toSub"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public static byte[] transform(byte[] toSub, int value)
        {
            toSub[toSub.Length-1] = (byte)(toSub[toSub.Length-1] + value);
            return toSub;
        }
        #endregion
    }
}
