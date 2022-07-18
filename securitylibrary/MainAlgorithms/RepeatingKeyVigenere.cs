using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            Dictionary<char, int> alphabetic = new Dictionary<char, int>();
            int value = 0;
            for (char c = 'a'; c <= 'z'; c++)
            {
                alphabetic.Add(c, value);
                value++;
            }
            string cipher_text = cipherText.ToLower();
            string plain_text = plainText.ToLower();
            string key_stream = "";
            int[] arr1 = new int[cipher_text.Length];
            for (int i = 0; i < cipher_text.Length; i++)
            {
                foreach (KeyValuePair<char, int> leter in alphabetic)
                {
                    if (cipher_text[i] == leter.Key)
                    {
                        arr1[i] = leter.Value;

                    }
                }

            }
            int[] arr2 = new int[plain_text.Length];
            for (int i = 0; i < plain_text.Length; i++)
            {
                
                foreach (KeyValuePair<char, int> leter in alphabetic)
                {
                    if (plain_text[i] == leter.Key)
                    {
                        arr2[i] = leter.Value;

                    }
                }

            }
            int result = 0;
             for(int i=0;i<cipher_text.Length;i++)
            {
                result = (arr1[i] - arr2[i] + 26) % 26;
                foreach (KeyValuePair<char, int> leter in alphabetic)
                {
                    if (result == leter.Value)
                    {
                        key_stream += leter.Key;
                    }
                }
               
            }

            int index = 0;
            for (int j = 3; j < key_stream.Length; j++)
                {
                if (key_stream[0] == key_stream[j] & key_stream[1] == key_stream[j + 1])
                    {
                    index = j;
                    break;

                    }
                }
            string key = "";
                for(int i=0;i<index;i++)
            {
                key += key_stream[i];
            }
            return key.ToUpper(); 
            //throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            Dictionary<char, int> alphabetic = new Dictionary<char, int>();
            int value = 0;
            for (char c = 'a'; c <= 'z'; c++)
            {
                alphabetic.Add(c, value);
                value++;
            }
            string cipher_text = cipherText.ToLower();
            string keysream = key.ToLower();
            int index = 0;
            if (key.Length < cipherText.Length)
            {
                for (int i = key.Length; i < cipher_text.Length; i++)
                {
                    keysream += keysream[index];
                    index++;
                }
            }
            int[] arr1 = new int[cipher_text.Length];
            for (int i = 0; i < cipher_text.Length; i++)
            {
                foreach (KeyValuePair<char, int> leter in alphabetic)
                {
                    if (cipher_text[i] == leter.Key)
                    {
                        arr1[i] = leter.Value;

                    }
                }

            }
            int[] arr2 = new int[keysream.Length];
            for (int i = 0; i < keysream.Length; i++)
            {
                foreach (KeyValuePair<char, int> leter in alphabetic)
                {
                    if (keysream[i] == leter.Key)
                    {
                        arr2[i] = leter.Value;

                    }
                }

            }
            int result = 0;
            
            string plain = "";
            for (int i = 0; i < cipher_text.Length; i++)
            {
                result = (arr1[i] - arr2[i] + 26) % 26;
                foreach (KeyValuePair<char, int> leter in alphabetic)
                {
                    if (result== leter.Value)
                    {
                        plain += leter.Key;
                    }
                }
               
            }
            return plain;

            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            Dictionary<char, int> alphabetic = new Dictionary<char, int>();
            int value = 0;
            for (char c = 'a'; c <= 'z'; c++)
            {
                alphabetic.Add(c, value);
                value++;
            }
            string plain_text = plainText.ToLower();
            string keysream = key.ToLower();
            int index = 0;
            if (key.Length < plainText.Length)
            {
                for (int i = key.Length; i < plainText.Length; i++)
                {
                    keysream += keysream[index];
                    index++;
                }
            }
            int[] arr1 = new int[plainText.Length];
            for (int i = 0; i < plainText.Length; i++) 
            { 
                foreach (KeyValuePair<char, int> leter in alphabetic)
                {
                if (plain_text[i]==leter.Key)
                {
                        arr1[i] = leter.Value;

                }
            }

        }
            int[] arr2 = new int[keysream.Length];
            for (int i = 0; i < keysream.Length; i++)
            {
                foreach (KeyValuePair<char, int> leter in alphabetic)
                {
                    if (keysream[i] == leter.Key)
                    {
                        arr2[i] = leter.Value;

                    }
                }

            }
            int result = 0;
               
            
            string cipher = "";
            for (int i = 0; i < plain_text.Length; i++)
            {
                result = (arr2[i] + arr1[i]) % 26;
                foreach (KeyValuePair<char, int> leter in alphabetic)
                {
                    if (result == leter.Value)
                    {
                        cipher += leter.Key;
                    }
                }
                
            }
            return cipher;
                //throw new NotImplementedException();
            }
    }
}