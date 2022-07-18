using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }


        public string Decrypt(string cipherText, string key)
        {

            string cipher_text = cipherText.ToLower();
            string keyword = key.ToLower();
            string alpha = "";
            int[] space_indexes = new int[20];
            int space_count = 0;

            for (int count = 0; count < cipher_text.Length; count += 1)
            {

                if (cipher_text[count] == ' ')
                {
                    cipher_text = cipher_text.Remove(count, 1);
                    space_indexes[space_count] = count;
                    space_count++;
                }

            }

            space_indexes[space_count] = -1; // assign the end of the spaces by putting the last element 

            for (char i = 'a'; i <= 'z'; i++)
            {
                alpha += i;

            }
            string variable = keyword + alpha;
            string merge = variable.Replace('j', 'i');

            for (int i = 0; i < merge.Length; i++)
            {
                for (int j = 0; j < i; j++)
                {
                    if (merge[i] == merge[j])
                    {
                        merge = merge.Remove(i, 1);
                        i--;
                    }
                }
            }
            char[,] matrix = new char[5, 5];
            int x = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {

                    matrix[i, j] = merge[x];
                    x++;
                }

            }
            // Decrypt

            int row1 = 0, col1 = 0;
            int row2 = 0, col2 = 0;
            string plain_text = "";
            for (int i = 0; i < cipher_text.Length; i += 2)
            {
                get_index(matrix, cipher_text[i], ref row1, ref col1);
                get_index(matrix, cipher_text[i + 1], ref row2, ref col2);
                if (row1 == row2)
                {
                    plain_text += matrix[row1, (col1 + 4) % 5];
                    plain_text += matrix[row2, (col2 + 4) % 5];
                }
                else if (col1 == col2)
                {
                    plain_text += matrix[(row1 + 4) % 5, col1];
                    plain_text += matrix[(row2 + 4) % 5, col2];
                }
                else
                {
                    plain_text += matrix[row1, col2];
                    plain_text += matrix[row2, col1];
                }

            }
            for (int i = 1; i < plain_text.Length - 1; i += 2)
            {
                if (plain_text[i] == 'x')
                {
                    if (plain_text[i - 1] == plain_text[i + 1])
                    {
                        plain_text = plain_text.Remove(i, 1);
                        i--;
                    }
                }
            }

            if (plain_text[plain_text.Length - 1] == 'x')
            {
                plain_text = plain_text.Remove(plain_text.Length - 1, 1);
            }

            for (int count = 0; space_indexes[count] != -1; count++)
            {
                plain_text.Insert(space_indexes[count] + count, " ");
            }

            return plain_text.ToUpper();
        }
        public string Encrypt(string plainText, string key)
        {
            string plain_text = plainText.ToLower();
            string keyword = key.ToLower();
            string alpha = "";
            for (int i = 0; i < plain_text.Length - 1; i += 2)
            {
                if (plain_text[i] == plain_text[i + 1])
                {
                    plain_text = plain_text.Insert(i + 1, "x");
                }
            }
            if (plain_text.Length % 2 != 0)
            {
                plain_text = plain_text + 'x';

            }
            for (char i = 'a'; i <= 'z'; i++)
            {
                alpha += i;

            }
            string variable = keyword + alpha.ToString();
            string merge = variable.Replace('j', 'i');
            for (int i = 0; i < merge.Length; i++)
            {
                for (int j = 0; j < i; j++)
                {
                    if (merge[i] == merge[j])
                    {
                        merge = merge.Remove(i, 1);
                        i--;
                    }
                }
            }
            char[,] matrix = new char[5, 5];
            int index = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {

                    matrix[i, j] = merge[index];
                    index++;
                }

            }

            int row1 = 0, col1 = 0;
            int row2 = 0, col2 = 0;
            string chipher = "";
            for (int i = 0; i < plain_text.Length; i += 2)
            {
                get_index(matrix, plain_text[i], ref row1, ref col1);
                get_index(matrix, plain_text[i + 1], ref row2, ref col2);
                if (row1 == row2)
                {
                    chipher += matrix[row1, (col1 + 1) % 5];
                    chipher += matrix[row2, (col2 + 1) % 5];
                }
                else if (col1 == col2)
                {
                    chipher += matrix[(row1 + 1) % 5, col1];
                    chipher += matrix[(row2 + 1) % 5, col2];
                }
                else
                {
                    chipher += matrix[row1, col2];
                    chipher += matrix[row2, col1];
                }

            }



            return chipher.ToUpper();
            //throw new NotImplementedException();
        }
        void get_index(char[,] matrix, char chr, ref int row, ref int col)
        {

            //keep looping in  the matrix until you find the character and then return its coordinates
            for (int row_count = 0, flag = 0; flag == 0; row_count++)
            {

                for (int col_count = 0; col_count < 5; col_count++)
                {

                    if (matrix[row_count, col_count] == chr)
                    {
                        flag = 1;
                        col = col_count;
                        row = row_count;
                        break;
                    }

                }

            }
        }
    }
}