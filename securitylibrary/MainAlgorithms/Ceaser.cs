using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public struct cipher
    {
        public int value;
        public char ch;
    };

    public class Ceaser : ICryptographicTechnique<string, int>
    {

        public string Encrypt(string plainText, int key)
        {
            cipher[] ci = new cipher[26];
            int index = 0;
            for (char i = 'a'; i <= 'z'; i++)
            {
                ci[index].ch = i;
                ci[index].value = index;
                index++;
            }
            string cipher_text = "";
            int cipher_index;
            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < index; j++)
                {
                    if (plainText[i] == ci[j].ch)
                    {
                        cipher_index = (ci[j].value + key) % 26;
                        cipher_text= cipher_text + ci[cipher_index].ch;
                    }
                }
            }


            return cipher_text;

            //throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, int key)
        {
            string ct = cipherText.ToLower();
            cipher[] ci = new cipher[26];
            int index = 0;
            for (char i = 'a'; i <= 'z'; i++)
            {
                ci[index].ch = i;
                ci[index].value = index;
                index++;
            }
            string plain_text = "";
            int plain_index;
            for (int i = 0; i < ct.Length; i++)
            {
                for (int j = 0; j <= 25; j++)
                {
                    if (ct[i] == ci[j].ch)
                    {

                        plain_index = (ci[j].value - key) % 26;
                        if (plain_index < 0)
                        {
                            plain_index = plain_index + 26;
                        }
                        plain_text+= ci[plain_index].ch;
                    }
                }
            }


            return plain_text.ToUpper();

            // throw new NotImplementedException();
        }

        public int Analyse(string plainText, string cipherText)
        {
            string ct = cipherText.ToLower();
            string pt = plainText.ToLower();
            cipher[] ci = new cipher[26];
            int index = 0;
            int result_index1 = 0;
            int result_index2 = 0;
            for (char i = 'a'; i <= 'z'; i++)
            {
                ci[index].ch = i;
                ci[index].value = index;
                index++;
            }
           

            for (int j = 0; j <= 25; j++)
            {
                if (ct[0] == ci[j].ch)
                {

                    result_index1 = ci[j].value;
                }
            }

            for (int j = 0; j <= 25; j++)
            {
                if (pt[0] == ci[j].ch)
                {
                    result_index2 = ci[j].value;
                    break;
                }
            }
            int key = (result_index1 - result_index2) % 26;
            if (key < 0)
            {
                key += 26;
            }

            return key;
            //throw new NotImplementedException();
        }
    }
}