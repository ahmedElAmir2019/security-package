using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string cipher_text = cipherText.ToLower();
            string plain_text = plainText.ToLower();
            int index = 0;
            char[] alpha = new char[26];
            char[] key = new char[26];
            char[] used = new char[26];

            for (char ch = 'a'; ch <= 'z'; ch++)
            {
                alpha[index] = ch;
                index++;
            }

            for (int i = 0; i < plain_text.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (plain_text[i] == alpha[j])
                    {
                        key[j] = cipher_text[i];
                    }

                }
            }
            for (int i = 0; i < cipher_text.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (cipher_text[i] == alpha[j])
                    {
                        used[j] = 't';
                    }
                }
            }
            for (int i = 0; i < 26; i++)
            {
                if (key[i] == '\0')
                {
                    for (int j = 0; j < 26; j++)
                    {
                        if (used[j] != 't')
                        {
                            key[i] = alpha[j];
                            used[j] = 't';
                            break;
                        }
                    }
                }
            }
            string keyword = "";
            for (int i = 0; i < key.Length; i++)
            {
                keyword += key[i];
            }
            return keyword;
            // throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            string cipher_text = cipherText.ToLower();
            string keyword = key.ToLower();
            int index = 0;
            char[] alpha = new char[26];
            for (char ch = 'a'; ch <= 'z'; ch++)
            {
                alpha[index] = ch;
                index++;
            }
            string plain_text = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (cipher_text[i] == keyword[j])
                    {
                        plain_text += alpha[j];
                    }
                }


            }
            return plain_text.ToUpper();

            // throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            string plain_text = plainText.ToLower();
            string keyword = key.ToLower();
            int index = 0;
            char[] alpha = new char[26];
            for (char ch = 'a'; ch <= 'z'; ch++)
            {
                alpha[index] = ch;
                index++;
            }
            string cipher_text = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (plain_text[i] == alpha[j])
                    {
                        cipher_text += keyword[j];
                    }
                }

                //throw new NotImplementedException();
            }
            return cipher_text;

        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            string cip = cipher.ToLower();
            char[] arr_frequency = { 'e', 't', 'a', 'o', 'i', 'n', 's', 'r', 'h', 'l', 'd', 'c', 'u', 'm', 'f', 'p', 'g', 'w', 'y', 'b', 'v', 'k', 'x', 'j', 'q', 'z' };
            Dictionary<char, int> dict1 = new Dictionary<char, int>();

            for (char c = 'a'; c <= 'z'; c++)
            {
                int count = 0;
                for (int j = 0; j < cip.Length; j++)
                {
                    if (c == cip[j])
                    {
                        count++;
                    }
                }
                dict1.Add(c, count);
            }
            int index = 0;
            char[] order_dic1 = new char[26];
            foreach (KeyValuePair<char, int> leter in dict1.OrderByDescending(key => key.Value))
            {

                order_dic1[index] = leter.Key;
                index++;
            }
            Dictionary<char, char> dict = new Dictionary<char, char>();
            string plaintext = "";
            for (int i = 0; i < 26; i++)
            {
                dict.Add(order_dic1[i], arr_frequency[i]);
            }
            for (int i = 0; i < cip.Length; i++)
            {
                foreach (KeyValuePair<char, char> leter in dict)
                {
                    if (leter.Key == cip[i])
                    {
                        plaintext += leter.Value;
                    }
                }

                
            }

            return plaintext;
        }
    }
}