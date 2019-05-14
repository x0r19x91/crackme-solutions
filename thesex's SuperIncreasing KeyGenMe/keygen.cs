using System;

/*
 * Usage : keygen.exe [username]
 */

class Keygen {
    static int seed = 0;
    static void Main(string[] args) {
        if (args.Length == 0) {
            return;
        }
        string user = args[0];
        foreach (char ch in user) {
            if (Char.IsLetter(ch)) {
                seed += Char.ToUpper(ch);
            }
        }
        NextRand();
        string[] A = new string[4];
        for (int i = 0; i < 4; ++i) {
            int t = 0;
            for (int j = 0; j < 7; ++j) {
                t = t << 1 | (NextRand() >> 6 & 1);
            }
            A[i] = t.ToString("X");
        }
        Console.WriteLine("[*] Serial: " + string.Join("-", A));
    }

    static int NextRand() {
        return seed = seed*0x41C64E6D + 0x3039;
    }
}