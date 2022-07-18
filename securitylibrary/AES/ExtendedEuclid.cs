using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            int Q, A1, A2, A3, B1, B2, B3 = 0;
            A1 = 1;
            A2 = 0;
            A3 = baseN;
            B1 = 0;
            B2 = 1;
            B3 = number;
            int old_A1, old_A2, old_A3 = 0;
            while (B3 >= 1)
            {
                if (B3 == 1)
                {
                    if (B2 < 1)
                        return B2 + baseN;
                    return B2;
                }
                old_A1 = A1;
                old_A2 = A2;
                old_A3 = A3;
                Q = A3 / B3;
                A1 = B1;
                A2 = B2;
                A3 = B3;
                B1 = old_A1 - B1 * Q;
                B2 = old_A2 - B2 * Q;
                B3 = old_A3 % B3;
            }
            return -1;
            //throw new NotImplementedException();
        }
    }
}
