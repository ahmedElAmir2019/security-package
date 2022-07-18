using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using MathNet.Numerics.LinearAlgebra;
using MathNet.Numerics.LinearAlgebra.Double;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<List<int>, List<int>>
    {
        public int determinant(Matrix<double> Matrix)
        {
            //det of matrix 3*3
            double det = Matrix[0, 0] * (Matrix[1, 1] * Matrix[2, 2] - Matrix[1, 2] * Matrix[2, 1]) -
                       Matrix[0, 1] * (Matrix[1, 0] * Matrix[2, 2] - Matrix[1, 2] * Matrix[2, 0]) +
                       Matrix[0, 2] * (Matrix[1, 0] * Matrix[2, 1] - Matrix[1, 1] * Matrix[2, 0]);
            //check det less than 26 and greater than 0 and check if det has inverse number 
            if ((int)det % 26 >= 0)
                det = (int)det % 26;

            else
                det = (int)det % 26 + 26;
            for (int i = 0; i < 26; i++)
            {
                if (det * i % 26 == 1)
                {

                    return i;
                }
            }

            return -1;

        }
        // inverse of matrix 3*3 = transpose matrix * inverse det of matrix (1/det)
        public Matrix<double> Inverse3(Matrix<double> Matrix, int det)
        {

            Matrix<double> resMat = DenseMatrix.Create(3, 3, 0.0);

            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    int x, y, x1, y1;

                    if (i == 0)
                        x = 1;
                    else x = 0;
                    if (j == 0)
                        y = 1;
                    else y = 0;
                    if (i == 2)
                        x1 = 1;
                    else x1 = 2;
                    if (j == 2)
                        y1 = 1;
                    else y1 = 2;
                    double r = ((Matrix[x, y] * Matrix[x1, y1] - Matrix[x, y1] * Matrix[x1, y]) * Math.Pow(-1, i + j) * det) % 26;
                    //check all element non negative 
                    if (r >= 0)
                    {
                        resMat[i, j] = r;
                    }
                    else resMat[i, j] = r + 26;

                }
            }
            return resMat;
        }

        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<int> DefaultKey = new List<int>();
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        for (int l = 0; l < 26; l++)
                        {
                            DefaultKey = new List<int>(new[] { i, j, k, l });
                            List<int> ResultEnc = Encrypt(plainText, DefaultKey);
                            //check if plaintext*defaultkey=ciphertext (matrix 2*2)
                            if (ResultEnc.SequenceEqual(cipherText))
                            {
                                return DefaultKey;
                            }

                        }
                    }
                }
            }

            throw new InvalidAnlysisException();
        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            List<double> keyD = key.ConvertAll(x => (double)x);
            List<double> CipherD = cipherText.ConvertAll(x => (double)x);
            int m = Convert.ToInt32(Math.Sqrt((key.Count)));
            Matrix<double> keyMatrix = DenseMatrix.OfColumnMajor(m, (int)key.Count / m, keyD.AsEnumerable());
            Matrix<double> CipherMatrix = DenseMatrix.OfColumnMajor(m, (int)cipherText.Count / m, CipherD.AsEnumerable());
            List<int> plain = new List<int>();
            // if key matrix 3*3
            if (keyMatrix.ColumnCount == 3)
            {
                keyMatrix = Inverse3(keyMatrix.Transpose(), determinant(keyMatrix));
            }

            //key matrix 2*2
            else
            {
                // ex key list{a,b,c,d} det=ab-cd
                int det = (int)(keyMatrix[0, 0] * keyMatrix[1, 1] - keyMatrix[0, 1] * keyMatrix[1, 0]);
                if (det % 26 >= 0)
                    det = det % 26;

                else
                    det = det % 26 + 26;
                // check det has inverse num or not (det*inverse det=1)
                int b = -1;
                for (int i = 0; i < 26; i++)
                {
                    if (det * i % 26 == 1)
                    {
                        b = i;

                    }
                }
                //throw exceptionn if det not has inverse 
                if (b == -1)
                {
                    throw new SystemException();
                }
                //inverse of key matrix =1/det* transpose {d,-c,-b,a}

                keyMatrix = keyMatrix.Inverse();
            }



            // plain matrix =cipher matrux * inverse of key matrix 
            List<double> result = new List<double>();

            for (int i = 0; i < CipherMatrix.ColumnCount; i++)
            {

                result = (((CipherMatrix.Column(i)) * keyMatrix) % 26).ToList();
                for (int j = 0; j < result.Count; j++)
                {
                    //check All elements are nonnegative and less than 26

                    int x;
                    if ((int)result[j] >= 0)
                    {
                        x = (int)result[j];
                    }
                    else
                        x = (int)result[j] + 26;


                    plain.Add(x);
                }
            }



            return plain;
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {

            int m = (int)Math.Sqrt(key.Count());
            int[,] newkey = new int[m, m];
            for (int i = 0; i < key.Count(); i++)
            {
                newkey[(i / m), (i % m)] = key[i];
                
            }
            

            int column = ((int)((plainText.Count()) / (Math.Sqrt(key.Count()))));
            int raw = (int)Math.Sqrt(key.Count());
            int[,] text_matrix = new int[raw, column];
            int[,] cipher_matrix = new int[raw, column];

            int iterator = 0;
            foreach (char c in plainText)
            {
               
                text_matrix[(iterator % raw), (iterator / raw)] = c;
                iterator++;
            }
            int[] slicing = new int[raw];
            for (int i = 0; i < column; i++)
            {
                for (int j = 0; j < slicing.Length; j++)
                {
                    slicing[j] = text_matrix[j, i];
                }
                for (int s = 0; s < raw; s++)
                {
                    int b = 0;
                    for (int j = 0; j < raw; j++)
                    {
                        b = b + (slicing[j] * newkey[s, j]);
                        
                    }
                    b = b % 26;
                    
                    cipher_matrix[s, i] = b;
                }
            }
            List<int> ci = new List<int>();
            for (int s = 0; s < column; s++)
            {
                int b = 0;
                for (int j = 0; j < raw; j++)
                {
                    ci.Add(cipher_matrix[j, s]);
                }

            }
            return ci;
            //throw new NotImplementedException();
        }


        public string Encrypt(string plainText, string key)
        {

            throw new NotImplementedException();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            List<double> CipherD = cipher3.ConvertAll(x => (double)x);
            List<double> PlainD = plain3.ConvertAll(x => (double)x);
            //m is num of row in matrix cipher and plain
            int m = Convert.ToInt32(Math.Sqrt((CipherD.Count)));
            //convert two list (cipher ,plain)to matrix (datatype double)
            Matrix<double> CipherMatrix = DenseMatrix.OfColumnMajor(m, (int)cipher3.Count / m, CipherD.AsEnumerable());
            Matrix<double> PlainMatrix = DenseMatrix.OfColumnMajor(m, (int)plain3.Count / m, PlainD.AsEnumerable());
            Matrix<double> KMatrix = DenseMatrix.Create(3, 3, 0);
            //key matrix =transposee(inverse of plain text * cipher test) 
           PlainMatrix = Inverse3(PlainMatrix.Transpose(), determinant(PlainMatrix)) ;
            KMatrix = (CipherMatrix * PlainMatrix)%26;
            List<double> list = KMatrix.Transpose().Enumerate().ToList();
            List<int> defaultkey = list.ConvertAll(x => (int)x);
            return defaultkey;
            //throw new NotImplementedException();
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
    }
}
