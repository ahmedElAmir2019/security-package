using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            //to remove repeat and calculate lenght of key
            var unique1 = new HashSet<char>(plainText);
            var unique2 = new HashSet<char>(cipherText);
            string pt_removeRepeat = plainText, cp_removeRepeat = cipherText;
            int index1, index2 = 0;
            int lenghtOfKey;

            if (cipherText[0] == cipherText[1])
            {
                pt_removeRepeat = "";
                cp_removeRepeat = "";
                foreach (char c in unique1)
                    pt_removeRepeat += c;
                foreach (char c in unique2)
                    cp_removeRepeat += c;
                index1 = pt_removeRepeat.IndexOf(cp_removeRepeat[0]);
                index2 = pt_removeRepeat.IndexOf(cp_removeRepeat[1]);
                lenghtOfKey = Math.Abs(index2 - index1) + 1;
                Console.WriteLine(lenghtOfKey);
            }
            else
            {
                index1 = pt_removeRepeat.IndexOf(cp_removeRepeat[0]);
                index2 = pt_removeRepeat.IndexOf(cp_removeRepeat[1]);
                lenghtOfKey = Math.Abs(index2 - index1);
                Console.WriteLine(lenghtOfKey);
            }



            float num = (float)plainText.Length / lenghtOfKey;
            int rowCount = (int)Math.Ceiling(num);
            int counttt = plainText.Length;
            if ((plainText.Length % lenghtOfKey) != 0)
            {

                while (counttt % lenghtOfKey != 0)
                {
                    counttt++;
                }
                counttt = counttt - plainText.Length;
                for (int i = 0; i < counttt; i++)
                    plainText += "x";


            }
            char[,] mutrix = new char[rowCount, lenghtOfKey];
            int index = 0;

            for (int i = 0; i < rowCount; i++)
            {
                for (int j = 0; j < lenghtOfKey; j++)
                {
                    mutrix[i, j] = plainText[index];
                    index++;
                }
            }
            string word = "";
            if (!cipherText.Contains("x"))
            {
                for (int i = 0; i < lenghtOfKey; i++)
                {
                    for (int j = 0; j < rowCount; j++)
                    {
                        word += mutrix[j, i];
                    }

                    if (word.Contains("x"))
                    {
                        word = word.Substring(0, rowCount - 1);
                        int c = cipherText.IndexOf(word);
                        cipherText = cipherText.Insert(c + (int)num, "x");

                    }
                    word = "";
                }
            }
            string wordOfcipher = "";
            string wordOfmutrix = "";
            List<int> key = new List<int>();
            int count = 0;
            for (int j = 0; j < lenghtOfKey; j++)
            {
                for (int n = 0; n < rowCount; n++)
                {
                    wordOfmutrix += mutrix[n, j];
                }

                for (int i = 0; i < lenghtOfKey; i++)
                {
                    wordOfcipher += cipherText.Substring(count, rowCount);
                    count += rowCount;
                    if (wordOfcipher == wordOfmutrix)
                    {
                        key.Add(i + 1);
                        wordOfcipher = "";

                    }
                    else
                        wordOfcipher = "";
                }
                count = 0;
                wordOfmutrix = "";

            }

            return key;
            //throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int rowCount = cipherText.Length / key.Count;
            char[,] mutrix = new char[rowCount, key.Count];
            string pt = "";
            int index_cipher = 0;
            for (int i = 0; i < key.Count; i++)
            {
                for (int j = 0; j < key.Count; j++)
                {
                    if (i + 1 == key[j])
                    {
                        for (int row = 0; row < rowCount; row++)
                        {
                            mutrix[row, j] = cipherText[index_cipher];
                            index_cipher++;
                        }
                        break;
                    }
                }


            }
            for (int i = 0; i < rowCount; i++)
            {
                for (int j = 0; j < key.Count; j++)
                    pt += mutrix[i, j];
            }
            return pt;
            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            string cipher = "";
            float num = (float)plainText.Length / key.Count;
            int rowCount = (int)Math.Ceiling(num);
            if ((plainText.Length % key.Count) != 0)
            {
                for (int i = 0; i < rowCount; i++)
                    plainText += "x";
            }
            char[,] matrix = new char[rowCount, key.Count];
            int index = 0;

            for (int i = 0; i < rowCount; i++)
            {
                for (int j = 0; j < key.Count; j++)
                {
                    if (plainText[index].Equals(' ') || plainText[index] == '\0')
                    {
                        index++;
                        j--;
                    }
                    else
                    {
                        matrix[i, j] = plainText[index];
                        index++;
                    }
                }
            }

            for (int i = 0; i < key.Count; i++)
            {
                for (int j = 0; j < key.Count; j++)
                {
                    if (i + 1 == key[j])
                    {
                        for (int row = 0; row < rowCount; row++)
                        {
                            cipher += matrix[row, j];
                        }
                    }

                }
            }
            return cipher;
            // throw new NotImplementedException();
        }
    }
}
