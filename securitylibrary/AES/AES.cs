﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
       public static byte[,] sbox = {   {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
                                            {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
                                            {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
                                            {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
                                            {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
                                            {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
                                            {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
                                            {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
                                            {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
                                            {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
                                            {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
                                            {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
                                            {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
                                            {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
                                            {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
                                            {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16} };


       public static byte[,] sboxInverse = { { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb },
                                                        { 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb },
                                                        { 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e },
                                                        { 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 },
                                                        { 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92 },
                                                        { 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 },
                                                        { 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06 },
                                                        { 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b },
                                                        { 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73 },
                                                        { 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e },
                                                        { 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b },
                                                        { 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4 },
                                                        { 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f },
                                                        { 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef },
                                                        { 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 },
                                                        { 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d } };

        int Rcon_index = 0;
        public static byte[,] Rcon = { {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 },
                         {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
                         {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
                         {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
        };

        public static byte[,] galoisField = {  {0x02, 0x03, 0x01, 0x01},
                                 {0x01, 0x02, 0x03, 0x01},
                                 {0x01, 0x01, 0x02, 0x03},
                                 {0x03, 0x01, 0x01, 0x02}
        };

        public static byte[,] galoisFieldInverse =  {   {0x0e, 0x0b, 0x0d, 0x09},
                                          {0x09, 0x0e, 0x0b, 0x0d},
                                          {0x0d, 0x09, 0x0e, 0x0b},
                                          {0x0b, 0x0d, 0x09, 0x0e}
        };
        public static byte[,] key_expansion = new byte[44, 4];
        public static byte[] Rotword(byte[] word)
        {
            byte first = word[0];
            for (int i = 0; i < 3; i++)
                word[i] = word[i + 1];
            word[3] = first;
            return word;
        }
        /*
         public int whereMySBox(string a)
        {
            int aR= Convert.ToInt32(a[0].ToString(), 16);
            int aL = Convert.ToInt32(a[1].ToString(), 16);
            int res = aR * 16 + aL;
            //Console.WriteLine(res.ToString() + ' ');
            return res;
        }
        */

        public static byte[] Sub_Byte(byte[] word)
        {
            byte[] ret = new byte[4];
            int newI;
            int newJ;
            for (int i = 0; i < 4; i++)
            {
                string tmp = Convert.ToString(word[i], 16);
                if (tmp.Length == 1)
                {
                    newI = 0;
                    newJ = Convert.ToInt32(tmp[0].ToString(), 16);
                }
                else
                {
                    newI = Convert.ToInt32(tmp[0].ToString(), 16);
                    newJ = Convert.ToInt32(tmp[1].ToString(), 16);
                }
                ret[i] = sbox[newI, newJ];
            }
            return ret;
        }
        public static byte[] xor(byte[] first, byte[] second, byte[] third, int is_multiple_of_4)
        {
            byte[] ret = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                string tmp;
                if (is_multiple_of_4 == 0)
                    tmp = Convert.ToString(first[i] ^ second[i], 16);
                else
                    tmp = Convert.ToString(first[i] ^ second[i] ^ third[i], 16);

                ret[i] = Convert.ToByte(tmp, 16);

            }


            return ret;
        }

        string makeString(byte[,] matrix)
        {
            StringBuilder str = new StringBuilder();
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    var temp = Convert.ToString(matrix[j, i], 16);
                    if (temp.Length < 2)
                    {
                        str.Append("0" + temp);
                    }
                    else str.Append(temp);
                }
            }
            return str.ToString().ToUpper().Insert(0, "0x");
        }

        public static byte[,] makeMatrix(string str)
        {
            byte[,] matrix = new byte[4, 4];

            int k = 2;
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    string tmp = "0x" + str[k] + str[k + 1];
                    matrix[i, j] = Convert.ToByte(tmp, 16);
                    k += 2;
                }
            }
            return matrix;
        }

        public static byte[,] makeByteMatrix2(string str)
        {
            byte[,] matrix = new byte[4, 4];

            int k = 2;
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    string tmp = "0x" + str[k] + str[k + 1];
                    matrix[j, i] = Convert.ToByte(tmp, 16);
                    k += 2;
                }
            }
            return matrix;
        }

        void put_key(string key)
        {
            byte[,] key_arr = new byte[4, 4];
            key_arr = makeByteMatrix2(key);
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    key_expansion[i, j] = key_arr[i, j];

        }
        public static byte[,] get_key_matrix(int index)
        {
            byte[,] mat = new byte[4, 4];
            int row = 0, col = 0;
            for (int i = index * 4; i < index * 4 + 4; i++)
            {
                col = 0;
                for (int j = 0; j < 4; j++)
                {
                    mat[col, row] = key_expansion[i, j];
                    col++;
                }
                row++;
            }
            return mat;
        }
         byte[,] RoundKey(byte[,] matrix, int Round_index)
        {
            byte[,] key_round;
            key_round = get_key_matrix(Round_index);

            print_mat(key_round);

            print_mat(matrix);

            string tmp;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    tmp = Convert.ToString(key_round[i, j] ^ matrix[i, j], 16);
                    key_round[i, j] = Convert.ToByte(tmp, 16);
                }
            }
            return key_round;
        }
        void implement_key_expansion()
        {
            byte[] first = new byte[4];
            byte[] second = new byte[4];
            byte[] third = new byte[4];
            byte[] final = new byte[4];
            for (int i = 4; i < 44; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    first[j] = key_expansion[i - 1, j];
                    second[j] = key_expansion[i - 4, j];
                    if (Rcon_index < 10)
                        third[j] = Rcon[j, Rcon_index];
                }
                if (i % 4 == 0)
                {
                   
                    Rcon_index++;
                    first = Rotword(first);
                    first = Sub_Byte(first);
                    final = xor(first, second, third, 1);
                }
                else
                    final = xor(first, second, third, 0);

                for (int j = 0; j < 4; j++)
                {
                    
                    key_expansion[i, j] = final[j];
                }

            }
        }
        void print_key_matrix()
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 44; j++)
                {
                    Console.Write(string.Join(", ", key_expansion[j, i].ToString("X2")));
                    Console.Write(" ");
                }
                Console.WriteLine();
            }
        }
        void print_mat(byte[,] mat)
        {

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Console.Write(string.Join(", ", mat[i, j].ToString("X2")));
                    Console.Write(" ");
                }
                Console.WriteLine();
            }

            Console.WriteLine("");
        }

        public static byte[,] mixCols(byte[,] shiftedmatrix)
        {
            List<byte> mixedMat = new List<byte>();
            byte[] arrayXor = new byte[4];
            byte[,] mixedColsMat = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        if (galoisField[j, k] == 2)
                        {
                            arrayXor[k] = advancedmultiplybyTwo(shiftedmatrix[k, i]);
                        }
                        if (galoisField[j, k] == 3)
                        {
                            arrayXor[k] = Convert.ToByte(advancedmultiplybyTwo(shiftedmatrix[k, i]) ^ shiftedmatrix[k, i]);
                        }

                        if (galoisField[j, k] == 1)
                        {
                            arrayXor[k] = shiftedmatrix[k, i];
                        }
                    }
                    var cell = arrayXor[0] ^ arrayXor[1] ^ arrayXor[2] ^ arrayXor[3];
                    mixedColsMat[j, i] = Convert.ToByte(cell);
                }
            }
            return mixedColsMat;
        }

        public static byte advancedmultiplybyTwo(byte x)
        {
            byte ret;
            UInt32 temp = Convert.ToUInt32(x << 1);
            ret = (byte)(temp & 0xFF);
            if (x > 127)
                ret = Convert.ToByte(ret ^ 27);
            return ret;
        }

        public static byte[,] mixColsInverse(byte[,] shiftedmatrix)
        {
            List<byte> mixedMat = new List<byte>();
            byte[] arrayXor = new byte[4];
            byte[,] mixedColsMat = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        if (galoisFieldInverse[j, k] == 0x9)
                        {
                            byte x0 = shiftedmatrix[k, i];
                            byte x1 = advancedmultiplybyTwo(x0);
                            byte x2 = advancedmultiplybyTwo(x1);
                            byte x3 = advancedmultiplybyTwo(x2);
                            arrayXor[k] = Convert.ToByte(x3 ^ x0);
                        }
                        if (galoisFieldInverse[j, k] == 0xB)
                        {
                            byte x0 = shiftedmatrix[k, i];
                            byte x1 = advancedmultiplybyTwo(x0);
                            byte x2 = advancedmultiplybyTwo(x1);
                            byte x3 = advancedmultiplybyTwo(x2);
                            arrayXor[k] = Convert.ToByte(x3 ^ x0 ^ x1);

                        }
                        if (galoisFieldInverse[j, k] == 0xD)
                        {
                            byte x0 = shiftedmatrix[k, i];
                            byte x1 = advancedmultiplybyTwo(x0);
                            byte x2 = advancedmultiplybyTwo(x1);
                            byte x3 = advancedmultiplybyTwo(x2);
                            arrayXor[k] = Convert.ToByte(x3 ^ x2 ^ x0);
                         
                        }

                        if (galoisFieldInverse[j, k] == 0xE)
                        {
                            byte x0 = shiftedmatrix[k, i];
                            byte x1 = advancedmultiplybyTwo(x0);
                            byte x2 = advancedmultiplybyTwo(x1);
                            byte x3 = advancedmultiplybyTwo(x2);
                            arrayXor[k] = Convert.ToByte(x3 ^ x2 ^ x1);

                        }
                    }
                    var cell = arrayXor[0] ^ arrayXor[1] ^ arrayXor[2] ^ arrayXor[3];
                    mixedColsMat[j, i] = Convert.ToByte(cell);
                }
            }
            return mixedColsMat;
        }

        public static byte[,] initial_round(byte[,] state)
        {
            string tmp;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    tmp = Convert.ToString(state[j, i] ^ key_expansion[i, j], 16);

                    state[j, i] = Convert.ToByte(tmp, 16);
                }
            }
            return state;
        }
        public static byte[,] substituteMatrix(byte[,] matrix)
        {
            byte[,] newMatrix = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string tmp = Convert.ToString(matrix[i, j], 16);
                    int newI, newJ;
                    if (tmp.Length == 1)
                    {
                        newI = 0;
                        newJ = Convert.ToInt32(tmp[0].ToString(), 16);
                    }
                    else
                    {
                        newI = Convert.ToInt32(tmp[0].ToString(), 16);
                        newJ = Convert.ToInt32(tmp[1].ToString(), 16);
                    }


                    newMatrix[i, j] = sbox[newI, newJ];
                }
            }
            return newMatrix;
        }
        public static byte[,] substituteMatrixInverse(byte[,] matrix)
        {
            byte[,] newMatrix = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string tmp = Convert.ToString(matrix[i, j], 16);
                    int newI, newJ;
                    if (tmp.Length == 1)
                    {
                        newI = 0;
                        newJ = Convert.ToInt32(tmp[0].ToString(), 16);
                    }
                    else
                    {
                        newI = Convert.ToInt32(tmp[0].ToString(), 16);
                        newJ = Convert.ToInt32(tmp[1].ToString(), 16);
                    }


                    newMatrix[i, j] = sboxInverse[newI, newJ];
                }
            }
            return newMatrix;
        }

        public static byte[] shiftRow(byte[] row, int n)
        {
            UInt32 number = 0;
            for (int i = 0; i < 4; i++)
            {

                number += Convert.ToUInt32(row[i]);
                if (i != 3) number = number << 8;
            }
            number = ((number << (n * 8)) | (number) >> (32 - (n * 8)));

            byte[] newRow = new byte[4];
            for (int i = 3; i >= 0; i--)
            {
                newRow[i] = (byte)(number & 0xFF);
                number = number >> 8;
            }
            return newRow;
        }
        public static byte[,] shiftMatrix(byte[,] matrix)
        {
            byte[,] newMatrix = new byte[4, 4];
            byte[] row = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    row[j] = matrix[i, j];
                }
                row = shiftRow(row, i);
                for (int j = 0; j < 4; j++)
                {
                    newMatrix[i, j] = row[j];
                }
            }
            return newMatrix;
        }
        public static byte[] shiftRowInverse(byte[] row, int n)
        {
            UInt32 number = 0;
            for (int i = 0; i < 4; i++)
            {

                number += Convert.ToUInt32(row[i]);
                if (i != 3) number = number << 8;
            }
            number = ((number >> (n * 8)) | (number) << (32 - (n * 8)));

            byte[] newRow = new byte[4];
            for (int i = 3; i >= 0; i--)
            {
                newRow[i] = (byte)(number & 0xFF);
                number = number >> 8;
            }
            return newRow;
        }
        public static byte[,] shiftMatrixInverse(byte[,] matrix)
        {
            byte[,] newMatrix = new byte[4, 4];
            byte[] row = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    row[j] = matrix[i, j];
                }
                row = shiftRowInverse(row, i);
                for (int j = 0; j < 4; j++)
                {
                    newMatrix[i, j] = row[j];
                }
            }
            return newMatrix;
        }

        public static byte[,] xorMatrix(byte[,] matrix, byte[,] key)
        {
            byte[,] newMatrix = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string tmp = Convert.ToString(matrix[i, j] ^ key[i, j], 16);
                    newMatrix[i, j] = Convert.ToByte(tmp, 16);
                }
            }
            return newMatrix;
        }
        public byte[,] finalRound(byte[,] state)
        {
            state = substituteMatrix(state);
            print_mat(state);
            
            state = shiftMatrix(state);
            print_mat(state);
          
            state = RoundKey(state, 10);
            print_mat(state);
           
            return state;
        }
        byte[,] finalRoundDecrypt(byte[,] state)
        {
            state = RoundKey(state, 10);
            print_mat(state);
            state = shiftMatrixInverse(state);
            print_mat(state);
            state = substituteMatrixInverse(state);
            print_mat(state);
            return state;
        }
        byte[,] main_rounds(byte[,] state, int round)
        {
            state = substituteMatrix(state);
            print_mat(state);
            
            state = shiftMatrix(state);
            print_mat(state);
            state = mixCols(state);
            print_mat(state);
            state = RoundKey(state, round);
            print_mat(state);
            return state;
        }
        byte[,] main_rounds_decryption(byte[,] state, int round)
        {
            state = RoundKey(state, round);
            print_mat(state);
            state = mixColsInverse(state);
            print_mat(state);
            state = shiftMatrixInverse(state);
            print_mat(state);
            state = substituteMatrixInverse(state);
            print_mat(state);
            return state;
        }
        byte[,] firstRoundDecryption(byte[,] state)
        {
            state = RoundKey(state, 0);
            return state;
        }
        public override string Decrypt(string cipherText, string key)
        {

            byte[,] state = makeMatrix(cipherText);
            put_key(key);
            implement_key_expansion();
            state = finalRoundDecrypt(state);
            print_mat(state);

            for (int i = 9; i > 0; i--)
            {
                state = main_rounds_decryption(state, i);
            }

            state = firstRoundDecryption(state);
            print_mat(state);
            return makeString(state);
        }

        public override string Encrypt(string plainText, string key)
        {
            byte[,] state = makeMatrix(plainText);
            put_key(key);
            implement_key_expansion();
            state = initial_round(state);

            for (int i = 1; i < 10; i++)
            {
                state = main_rounds(state, i);
            }

            state = finalRound(state);
            return makeString(state);
        }
    }
}