using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {

        public string Decrypt(string cipherText, List<string> key)
        {

            string plint = DES_Decrypt(cipherText, key[1]);
            string cipher = DES_Encrypt(plint, key[0]);
            string p = DES_Decrypt(cipher, key[1]);
            return p;
            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, List<string> key)
        {
            string cipher = DES_Encrypt(plainText, key[0]);
            string plain = DES_Decrypt(cipher, key[1]);
            string c2 = DES_Encrypt(plain, key[0]);
            return c2;
            //throw new NotImplementedException();
        }

        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }
        public static string DES_Decrypt(string cipherText, string key)
        {
            int[,] TnitailPrementation = new int[8, 8] { { 58, 50, 42, 34, 26, 18, 10, 2 }, { 60, 52, 44, 36, 28, 20, 12, 4 }, { 62, 54, 46, 38, 30, 22, 14, 6 }, { 64, 56, 48, 40, 32, 24, 16, 8 }, { 57, 49, 41, 33, 25, 17, 9, 1 }, { 59, 51, 43, 35, 27, 19, 11, 3 }, { 61, 53, 45, 37, 29, 21, 13, 5 }, { 63, 55, 47, 39, 31, 23, 15, 7 } };
            int[,] PC_1 = new int[8, 7] { { 57, 49, 41, 33, 25, 17, 9 }, { 1, 58, 50, 42, 34, 26, 18 }, { 10, 2, 59, 51, 43, 35, 27 }, { 19, 11, 3, 60, 52, 44, 36 }, { 63, 55, 47, 39, 31, 23, 15 }, { 7, 62, 54, 46, 38, 30, 22 }, { 14, 6, 61, 53, 45, 37, 29 }, { 21, 13, 5, 28, 20, 12, 4 } };
            int[,] PC_2 = new int[8, 6] { { 14, 17, 11, 24, 1, 5 }, { 3, 28, 15, 6, 21, 10 }, { 23, 19, 12, 4, 26, 8 }, { 16, 7, 27, 20, 13, 2 }, { 41, 52, 31, 37, 47, 55 }, { 30, 40, 51, 45, 33, 48 }, { 44, 49, 39, 56, 34, 53 }, { 46, 42, 50, 36, 29, 32 } };
            int[] shift = new int[] { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
            int[,] EB = new int[8, 6] { { 32, 1, 2, 3, 4, 5 }, { 4, 5, 6, 7, 8, 9 }, { 8, 9, 10, 11, 12, 13 }, { 12, 13, 14, 15, 16, 17 }, { 16, 17, 18, 19, 20, 21 }, { 20, 21, 22, 23, 24, 25 }, { 24, 25, 26, 27, 28, 29 }, { 28, 29, 30, 31, 32, 1 } };
            int[,] s1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
            int[,] s2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
            int[,] s3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
            int[,] s4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
            int[,] s5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
            int[,] s6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
            int[,] s7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
            int[,] s8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };
            int[,] P = new int[8, 4] { { 16, 7, 20, 21 }, { 29, 12, 28, 17 }, { 1, 15, 23, 26 }, { 5, 18, 31, 10 }, { 2, 8, 24, 14 }, { 32, 27, 3, 9 }, { 19, 13, 30, 6 }, { 22, 11, 4, 25 } };
            int[,] IP_1 = new int[8, 8] { { 40, 8, 48, 16, 56, 24, 64, 32 }, { 39, 7, 47, 15, 55, 23, 63, 31 }, { 38, 6, 46, 14, 54, 22, 62, 30 }, { 37, 5, 45, 13, 53, 21, 61, 29 }, { 36, 4, 44, 12, 52, 20, 60, 28 }, { 35, 3, 43, 11, 51, 19, 59, 27 }, { 34, 2, 42, 10, 50, 18, 58, 26 }, { 33, 1, 41, 9, 49, 17, 57, 25 } };

            string binaryplainText = "";
            string binaryplainText_afterIP = "";
            string binaryKey = "";
            char[,] pt = new char[8, 8];
            char[,] PC_1k = new char[8, 7];
            string C = "";
            string D = "";
            binaryplainText = Convert.ToString(Convert.ToInt64(cipherText, 16), 2).PadLeft(64, '0');
            binaryKey = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');
            Console.WriteLine(binaryplainText);
            //step1 for plaintext
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    int index = TnitailPrementation[i, j];
                    pt[i, j] = binaryplainText[index - 1];
                    binaryplainText_afterIP += pt[i, j];
                }
            }
            //step1 for key
            string k = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 7; j++)
                {
                    int index = PC_1[i, j];
                    PC_1k[i, j] = binaryKey[index - 1];
                    k = k + PC_1k[i, j];
                    // Console.Write(PC_1k[i, j]);
                }
                // Console.WriteLine();
            }
            //to put c and d
            C = k.Substring(0, 28);
            D = k.Substring(28, 28);
            Console.WriteLine(C);
            Console.WriteLine(D);
            //to shift c and D
            List<string> c = new List<string>();
            List<string> d = new List<string>();
            c.Add(C);
            d.Add(D);
            for (int i = 0; i < 16; i++)
            {

                int v_ofshiftInArray = shift[i];
                string valueofshift = "";
                if (v_ofshiftInArray == 1)
                {
                    valueofshift += C[0];
                    C = C.Remove(0, 1);
                    C += valueofshift;
                    valueofshift = "";
                    valueofshift += D[0];
                    D = D.Remove(0, 1);
                    D += valueofshift;
                }
                else
                {
                    valueofshift += C.Substring(0, 2);
                    C = C.Remove(0, 2);
                    C += valueofshift;
                    valueofshift = "";
                    valueofshift += D.Substring(0, 2);
                    D = D.Remove(0, 2);
                    D += valueofshift;
                }
                c.Add(C);
                d.Add(D);
                // Console.WriteLine(C);
                //Console.WriteLine(D);
            }
            List<string> key16 = new List<string>();
            for (int i = 0; i < c.Count; i++)
            {
                key16.Add(c[i] + d[i]);
            }
            //to get 16 of key by pc2
            List<string> pc2_key = new List<string>();
            for (int x = 1; x < key16.Count; x++)
            {
                string key1 = key16[x];
                string newKey = "";
                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 6; j++)
                    {
                        int index = PC_2[i, j];
                        newKey += key1[index - 1];
                    }

                }
                pc2_key.Add(newKey);
                //Console.WriteLine(newKey);
            }
            //divide pt into lift and right
            string lift = binaryplainText_afterIP.Substring(0, 32);
            string right = binaryplainText_afterIP.Substring(32, 32);
            List<string> LIFT = new List<string>();
            List<string> RIGHT = new List<string>();
            LIFT.Add(lift);
            RIGHT.Add(right);
            //to swap
            for (int round = 0; round < 16; round++)
            {

                LIFT.Add(right);
                string r = "";
                char[,] pt_Right = new char[8, 6];
                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 6; j++)
                    {
                        int index = EB[i, j];
                        pt_Right[i, j] = right[index - 1];
                        r += pt_Right[i, j];
                    }
                    //Console.WriteLine();
                }
                string xorOFRight = "";
                for (int i = 0; i < pt_Right.Length; i++)
                {
                    if (pc2_key[pc2_key.Count - 1 - round][i] == r[i])
                    {
                        xorOFRight += "0";
                    }
                    else
                    {
                        xorOFRight += "1";
                    }

                }
                // Console.WriteLine(xorOFRight);
                //to divide into 8 block each block 6 bit
                List<string> sbox = new List<string>();
                string elemntof_sbox = "";
                for (int i = 0; i < 8; i++)
                {
                    elemntof_sbox = "";
                    elemntof_sbox += xorOFRight.Substring(i * 6, 6);
                    sbox.Add(elemntof_sbox);

                }
                string res = "";
                for (int i = 0; i < sbox.Count; i++)
                {
                    string block = sbox[i];
                    string rowbinary = "";
                    string colbinary = "";
                    rowbinary += block[0].ToString() + block[5].ToString();
                    colbinary += block.Substring(1, 4);
                    //Console.WriteLine(rowbinary);
                    int row = Convert.ToInt32(rowbinary, 2);
                    int col = Convert.ToInt32(colbinary, 2);
                    if (i == 0)
                    {

                        res += Convert.ToString(s1[row, col], 2).PadLeft(4, '0');

                    }
                    if (i == 1)
                    {

                        res += Convert.ToString(s2[row, col], 2).PadLeft(4, '0');

                    }
                    if (i == 2)
                    {

                        res += Convert.ToString(s3[row, col], 2).PadLeft(4, '0');

                    }
                    if (i == 3)
                    {

                        res += Convert.ToString(s4[row, col], 2).PadLeft(4, '0');

                    }
                    if (i == 4)
                    {

                        res += Convert.ToString(s5[row, col], 2).PadLeft(4, '0');

                    }
                    if (i == 5)
                    {

                        res += Convert.ToString(s6[row, col], 2).PadLeft(4, '0');

                    }
                    if (i == 6)
                    {

                        res += Convert.ToString(s7[row, col], 2).PadLeft(4, '0');

                    }
                    if (i == 7)
                    {

                        res += Convert.ToString(s8[row, col], 2).PadLeft(4, '0');
                    }
                }

                string P_Right = "";
                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        int index = P[i, j];
                        P_Right += res[index - 1].ToString();

                    }

                }

                string xorOfRight_LIFT = "";
                for (int i = 0; i < P_Right.Length; i++)
                {
                    if (LIFT[round][i] == P_Right[i])
                    {
                        xorOfRight_LIFT += "0";
                    }
                    else
                    {
                        xorOfRight_LIFT += "1";
                    }

                }
                Console.WriteLine(xorOfRight_LIFT);
                RIGHT.Add(xorOfRight_LIFT);
                right = xorOfRight_LIFT;
            }
            string temp = "";
            temp = LIFT[16];
            LIFT[16] = RIGHT[16];
            RIGHT[16] = temp;
            string resOfSwap = LIFT[16] + RIGHT[16];
            Console.WriteLine(resOfSwap);
            string plain = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    int index = IP_1[i, j];
                    plain += resOfSwap[index - 1];
                }
            }

            plain = "0x" + Convert.ToInt64(plain, 2).ToString("X").PadLeft(16, '0');
            return plain;
        }

        public static string DES_Encrypt(string plainText, string key)
        {
            int[,] TnitailPrementation = new int[8, 8] { { 58, 50, 42, 34, 26, 18, 10, 2 }, { 60, 52, 44, 36, 28, 20, 12, 4 }, { 62, 54, 46, 38, 30, 22, 14, 6 }, { 64, 56, 48, 40, 32, 24, 16, 8 }, { 57, 49, 41, 33, 25, 17, 9, 1 }, { 59, 51, 43, 35, 27, 19, 11, 3 }, { 61, 53, 45, 37, 29, 21, 13, 5 }, { 63, 55, 47, 39, 31, 23, 15, 7 } };
            int[,] PC_1 = new int[8, 7] { { 57, 49, 41, 33, 25, 17, 9 }, { 1, 58, 50, 42, 34, 26, 18 }, { 10, 2, 59, 51, 43, 35, 27 }, { 19, 11, 3, 60, 52, 44, 36 }, { 63, 55, 47, 39, 31, 23, 15 }, { 7, 62, 54, 46, 38, 30, 22 }, { 14, 6, 61, 53, 45, 37, 29 }, { 21, 13, 5, 28, 20, 12, 4 } };
            int[,] PC_2 = new int[8, 6] { { 14, 17, 11, 24, 1, 5 }, { 3, 28, 15, 6, 21, 10 }, { 23, 19, 12, 4, 26, 8 }, { 16, 7, 27, 20, 13, 2 }, { 41, 52, 31, 37, 47, 55 }, { 30, 40, 51, 45, 33, 48 }, { 44, 49, 39, 56, 34, 53 }, { 46, 42, 50, 36, 29, 32 } };
            int[] shift = new int[] { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
            int[,] EB = new int[8, 6] { { 32, 1, 2, 3, 4, 5 }, { 4, 5, 6, 7, 8, 9 }, { 8, 9, 10, 11, 12, 13 }, { 12, 13, 14, 15, 16, 17 }, { 16, 17, 18, 19, 20, 21 }, { 20, 21, 22, 23, 24, 25 }, { 24, 25, 26, 27, 28, 29 }, { 28, 29, 30, 31, 32, 1 } };
            int[,] s1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
            int[,] s2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
            int[,] s3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
            int[,] s4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
            int[,] s5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
            int[,] s6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
            int[,] s7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
            int[,] s8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };
            int[,] P = new int[8, 4] { { 16, 7, 20, 21 }, { 29, 12, 28, 17 }, { 1, 15, 23, 26 }, { 5, 18, 31, 10 }, { 2, 8, 24, 14 }, { 32, 27, 3, 9 }, { 19, 13, 30, 6 }, { 22, 11, 4, 25 } };
            int[,] IP_1 = new int[8, 8] { { 40, 8, 48, 16, 56, 24, 64, 32 }, { 39, 7, 47, 15, 55, 23, 63, 31 }, { 38, 6, 46, 14, 54, 22, 62, 30 }, { 37, 5, 45, 13, 53, 21, 61, 29 }, { 36, 4, 44, 12, 52, 20, 60, 28 }, { 35, 3, 43, 11, 51, 19, 59, 27 }, { 34, 2, 42, 10, 50, 18, 58, 26 }, { 33, 1, 41, 9, 49, 17, 57, 25 } };
            string plain_text = plainText;
            string binaryplainText = "";
            string binaryplainText_afterIP = "";
            string binaryKey = "";
            char[,] pt = new char[8, 8];
            char[,] PC_1k = new char[8, 7];
            string C = "";
            string D = "";
            binaryplainText = Convert.ToString(Convert.ToInt64(plain_text, 16), 2).PadLeft(64, '0');
            binaryKey = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');
            Console.WriteLine(binaryplainText);
            //step1 for plaintext
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    int index = TnitailPrementation[i, j];
                    pt[i, j] = binaryplainText[index - 1];
                    binaryplainText_afterIP += pt[i, j];
                    //Console.Write(pt[i,j]);
                }
                //Console.WriteLine();
            }
            //step1 for key
            string k = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 7; j++)
                {
                    int index = PC_1[i, j];
                    PC_1k[i, j] = binaryKey[index - 1];
                    k = k + PC_1k[i, j];
                    // Console.Write(PC_1k[i, j]);
                }
                // Console.WriteLine();
            }
            //to put c and d
            C = k.Substring(0, 28);
            D = k.Substring(28, 28);
            Console.WriteLine(C);
            Console.WriteLine(D);
            //to shift c and D
            List<string> c = new List<string>();
            List<string> d = new List<string>();
            c.Add(C);
            d.Add(D);
            for (int i = 0; i < 16; i++)
            {

                int v_ofshiftInArray = shift[i];
                string valueofshift = "";
                if (v_ofshiftInArray == 1)
                {
                    valueofshift += C[0];
                    C = C.Remove(0, 1);
                    C += valueofshift;
                    valueofshift = "";
                    valueofshift += D[0];
                    D = D.Remove(0, 1);
                    D += valueofshift;
                }
                else
                {
                    valueofshift += C.Substring(0, 2);
                    C = C.Remove(0, 2);
                    C += valueofshift;
                    valueofshift = "";
                    valueofshift += D.Substring(0, 2);
                    D = D.Remove(0, 2);
                    D += valueofshift;
                }
                c.Add(C);
                d.Add(D);
                // Console.WriteLine(C);
                //Console.WriteLine(D);
            }
            List<string> key16 = new List<string>();
            for (int i = 0; i < c.Count; i++)
            {
                key16.Add(c[i] + d[i]);
            }
            //to get 16 of key by pc2
            List<string> pc2_key = new List<string>();
            for (int x = 1; x < key16.Count; x++)
            {
                string key1 = key16[x];
                string newKey = "";
                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 6; j++)
                    {
                        int index = PC_2[i, j];
                        newKey += key1[index - 1];
                    }

                }
                pc2_key.Add(newKey);
                //Console.WriteLine(newKey);
            }
            //divide pt into lift and right
            string lift = binaryplainText_afterIP.Substring(0, 32);
            string right = binaryplainText_afterIP.Substring(32, 32);
            List<string> LIFT = new List<string>();
            List<string> RIGHT = new List<string>();
            LIFT.Add(lift);
            RIGHT.Add(right);
            //to swap
            for (int round = 0; round < 16; round++)
            {

                LIFT.Add(right);
                string r = "";
                char[,] pt_Right = new char[8, 6];
                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 6; j++)
                    {
                        int index = EB[i, j];
                        pt_Right[i, j] = right[index - 1];
                        r += pt_Right[i, j];
                    }
                    //Console.WriteLine();
                }
                string xorOFRight = "";
                for (int i = 0; i < pt_Right.Length; i++)
                {
                    if (pc2_key[round][i] == r[i])
                    {
                        xorOFRight += "0";
                    }
                    else
                    {
                        xorOFRight += "1";
                    }

                }
                // Console.WriteLine(xorOFRight);
                //to divide into 8 block each block 6 bit
                List<string> sbox = new List<string>();
                string elemntof_sbox = "";
                for (int i = 0; i < 8; i++)
                {
                    elemntof_sbox = "";
                    elemntof_sbox += xorOFRight.Substring(i * 6, 6);
                    sbox.Add(elemntof_sbox);

                }
                string res = "";
                for (int i = 0; i < sbox.Count; i++)
                {
                    string block = sbox[i];
                    string rowbinary = "";
                    string colbinary = "";
                    rowbinary += block[0].ToString() + block[5].ToString();
                    colbinary += block.Substring(1, 4);
                    //Console.WriteLine(rowbinary);
                    int row = Convert.ToInt32(rowbinary, 2);
                    int col = Convert.ToInt32(colbinary, 2);
                    if (i == 0)
                    {

                        res += Convert.ToString(s1[row, col], 2).PadLeft(4, '0');

                    }
                    if (i == 1)
                    {

                        res += Convert.ToString(s2[row, col], 2).PadLeft(4, '0');

                    }
                    if (i == 2)
                    {

                        res += Convert.ToString(s3[row, col], 2).PadLeft(4, '0');

                    }
                    if (i == 3)
                    {

                        res += Convert.ToString(s4[row, col], 2).PadLeft(4, '0');

                    }
                    if (i == 4)
                    {

                        res += Convert.ToString(s5[row, col], 2).PadLeft(4, '0');

                    }
                    if (i == 5)
                    {

                        res += Convert.ToString(s6[row, col], 2).PadLeft(4, '0');

                    }
                    if (i == 6)
                    {

                        res += Convert.ToString(s7[row, col], 2).PadLeft(4, '0');

                    }
                    if (i == 7)
                    {

                        res += Convert.ToString(s8[row, col], 2).PadLeft(4, '0');
                    }
                }

                string P_Right = "";
                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        int index = P[i, j];
                        P_Right += res[index - 1].ToString();

                    }

                }

                string xorOfRight_LIFT = "";
                for (int i = 0; i < P_Right.Length; i++)
                {
                    if (LIFT[round][i] == P_Right[i])
                    {
                        xorOfRight_LIFT += "0";
                    }
                    else
                    {
                        xorOfRight_LIFT += "1";
                    }

                }
                Console.WriteLine(xorOfRight_LIFT);
                RIGHT.Add(xorOfRight_LIFT);
                right = xorOfRight_LIFT;
            }
            string temp = "";
            temp = LIFT[16];
            LIFT[16] = RIGHT[16];
            RIGHT[16] = temp;
            string resOfSwap = LIFT[16] + RIGHT[16];
            Console.WriteLine(resOfSwap);
            string cipher = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    int index = IP_1[i, j];
                    cipher += resOfSwap[index - 1];
                }
            }

            cipher = "0x" + Convert.ToInt64(cipher, 2).ToString("X");
            return cipher;
        }

    }
}
