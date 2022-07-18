using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary


{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            int k = 0;
           string pt = plainText.ToLower();
           string ct = cipherText.ToLower();
            Console.WriteLine(pt[2]);
            for (int i = 2; i < ct.Length; i++)
            {

                if (ct[1] == pt[i])
                {

                    k = i;
                    break;

                }

            }

            return k;
        }









        public string Decrypt(string cipherText, int key)
        {
            double l = Convert.ToDouble(key);
            double c = (cipherText.Length) / l;
            c = Math.Ceiling(c);
            int columns = Convert.ToInt32(c);
            char[,] arr = new char[key, columns];
            string plainText = "";
            int k = 0;
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < columns; j++)
                {
                    if (k < cipherText.Length)
                        arr[i, j] = cipherText[k++];

                }

            }

            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < columns; j++)
                {
                    Console.Write(arr[i, j]);

                }

                Console.Write("\n");
            }

            for (int i = 0; i < columns; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    plainText += arr[j, i];

                }

            }

            return plainText;
        }

























        public string Encrypt(string plainText, int key)
        {

            double l = Convert.ToDouble(key);
            double c = (plainText.Length) / l;
            c = Math.Ceiling(c);
            int columns = Convert.ToInt32(c);
            char[,] arr = new char[key, columns];
            string cipherText = "";
            int k = 0;
            for (int i = 0; i < columns; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if (k < plainText.Length)
                        arr[j, i] = plainText[k++];

                }

            }

            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < columns; j++)
                {
                    Console.Write(arr[i, j]);

                }

                Console.Write("\n");
            }

            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < columns; j++)
                {
                    cipherText += arr[i, j];

                }

            }

            return cipherText;
        }
    }
}
