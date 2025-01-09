#include "aby3/sh3/Sh3Encryptor.h"
#include "aby3/sh3/Sh3Evaluator.h"
#include "aby3/sh3/Sh3Runtime.h"
#include "aby3/sh3/Sh3ShareGen.h"
#include <cryptoTools/Common/CLP.h>
#include "cryptoTools/Common/BitIterator.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <cryptoTools/Network/IOService.h>
#include <atomic>
#include "aby3-DB/DBServer.h"
#include <unordered_set>
#include <iostream>

using namespace oc;
using namespace aby3;
using namespace std;

using u32 = uint32_t;
using u64 = uint64_t;

#define fgh cout << "\n---------------------------------\n";
#define foru(i, a, b) for (int i = a; i < b; ++i)
#define ford(i, a, b) for (int i = a; i > b; --i)
#define IFparty0 if (idx == 0)
#define IFparty1 if (idx == 1)
#define IFparty2 if (idx == 2)

// i64 Sh3_Int_Vector_test(u64 n)
// {
//     IOService ios;
//     Session s01(ios, "127.0.0.1", SessionMode::Server, "01");
//     Session s10(ios, "127.0.0.1", SessionMode::Client, "01");
//     Session s02(ios, "127.0.0.1", SessionMode::Server, "02");
//     Session s20(ios, "127.0.0.1", SessionMode::Client, "02");
//     Session s12(ios, "127.0.0.1", SessionMode::Server, "12");
//     Session s21(ios, "127.0.0.1", SessionMode::Client, "12");

//     Channel chl01 = s01.addChannel("c");
//     Channel chl10 = s10.addChannel("c");
//     Channel chl02 = s02.addChannel("c");
//     Channel chl20 = s20.addChannel("c");
//     Channel chl12 = s12.addChannel("c");
//     Channel chl21 = s21.addChannel("c");

//     CommPkg comms[3];
//     comms[0] = {chl02, chl01};
//     comms[1] = {chl10, chl12};
//     comms[2] = {chl21, chl20};

//     bool failed = false;

//     Timer t;
//     u32 MOD = 10000;
//     i64Matrix a(n, 1);
//     PRNG prng(ZeroBlock);
//     cout << "a :\n";
//     foru(i, 0, n)
//     {
//         a(i) = abs(prng.get<i64>() % MOD);
//         cout << a(i) << ' ';
//     }
//     cout << endl;

//     int m = 0;
//     foru(i, 0, n) m = max(m, (int)ceil(log10(a(i) + 1) / log10(2)));
//     cout << "m = " << m << endl;
//     vector<vector<i64>> k_plain(m, vector<i64>(n, 0));
//     auto aa = a;
//     foru(i, 0, n) foru(j, 0, m)
//     {
//         k_plain[j][i] = aa[i] & 1;
//         aa[i] >>= 1;
//     }
//     // foru(i, 0, m) foru(j, 0, n) cout << k_plain[i][j] << " \n"[j == n - 1];

//     auto routine = [&](int idx)
//     {
//         vector<u32> pai_now(n), pai_nxt(n), inv_pai_now(n), inv_pai_nxt(n);
//         std::iota(pai_now.begin(), pai_now.end(), 0);
//         random_shuffle(pai_now.begin(), pai_now.end(), prng);
//         comms[idx].mPrev.asyncSendCopy(pai_now);
//         comms[idx].mNext.recv(pai_nxt);
//         foru(i, 0, n) inv_pai_now[pai_now[i]] = inv_pai_nxt[pai_nxt[i]] = i;

//         /*--------------Preparations---------------------------------------------------*/
//         PRNG prng;
//         Sh3Runtime rt(idx, comms[idx]);
//         Sh3Encryptor enc;
//         Sh3Evaluator eval;
//         Sh3Task task = rt.noDependencies();
//         enc.init(idx, comms[idx], sysRandomSeed());
//         eval.init(idx, comms[idx], sysRandomSeed());

//         si64 sone, szero;
//         if (idx == 0)
//         {
//             task = enc.localInt(rt.noDependencies(), 1, sone);
//             task = enc.localInt(task, 0, szero);
//             task.get();
//         }
//         else
//         {
//             task = enc.remoteInt(rt.noDependencies(), sone);
//             task = enc.remoteInt(task, szero);
//             task.get();
//         }
//         // sone = idx == 0 ? enc.localInt(comms[idx], 1) : enc.remoteInt(comms[idx]);
//         // szero = idx == 0 ? enc.localInt(comms[idx], 0) : enc.remoteInt(comms[idx]);

//         /*-----------------------------------test inv_pai-----------------------------*/
//         // vector<u32> test(n), test1(n), test2(n);
//         // std::iota(test.begin(), test.end(), 0);
//         // foru(i, 0, n) test1[pai_nxt[i]] = test[i];
//         // foru(i, 0, n) test2[inv_pai_nxt[i]] = test1[i];
//         // cout << "test:\n";
//         // foru(i, 0, n) cout << test[i] << " \n"[i == n - 1];
//         // cout << "test1:\n";
//         // foru(i, 0, n) cout << test1[i] << " \n"[i == n - 1];
//         // cout << "test2:\n";
//         // foru(i, 0, n) cout << test2[i] << " \n"[i == n - 1];

//         /**
//          * @Method Reshare Party i-1 和 i+1, reshare x to Party i
//          * @param x 需要reshare的数
//          * @param i reshare的接收方
//          *
//          * @return void
//          */
//         auto Reshare = [&](si64 &x, u32 i) -> void
//         {
//             si64 tmp;
//             u32 pre = (i + 2) % 3, nxt = (i + 1) % 3;
//             if (idx == i)
//             {
//                 // t.setTimePoint("reshare");
//                 tmp = enc.reshareRemote(comms[i]);
//                 comms[i].mPrev.recv(x.mData[1]);
//                 comms[i].mNext.recv(x.mData[0]);
//             }
//             else if (idx == nxt)
//             {
//                 tmp = enc.reshareLocal(comms[nxt], 0, nxt);
//                 x = x + tmp;
//                 comms[nxt].mPrev.asyncSendCopy(x.mData[1]);
//             }
//             else if (idx == pre)
//             {
//                 tmp = enc.reshareLocal(comms[pre], 0, nxt);
//                 x = x + tmp;
//                 comms[pre].mNext.asyncSendCopy(x.mData[0]);
//             }
//         };

//         /**
//          * @Method ReshareVec Party i-1 和 i+1, reshare vector_x to Party i
//          * @param vec_x 需要reshare的vector
//          * @param i reshare的接收方
//          *
//          * @return void
//          */
//         auto ReshareVec = [&](vector<si64> &vec_x, u32 i) -> void
//         {
//             for (auto &x : vec_x)
//                 Reshare(x, i);
//         };

//         /**
//          * @Method Shuffle 完整的Shuffling protocol
//          * @param a 需要shuffle的vector<si64>
//          *
//          * @return vector<si64>
//          */
//         auto Shuffle = [&](vector<si64> a)
//         {
//             vector<si64> b(n);
//             for (u32 i = 0; i <= 2; ++i)
//             {
//                 if (idx == i)
//                 {
//                     for (u32 j = 0; j < n; ++j)
//                         b[pai_now[j]] = a[j];
//                     // cout << "party" << idx << "shuffle!\n";
//                 }
//                 else if (idx == (i + 2) % 3)
//                 {
//                     for (u32 j = 0; j < n; ++j)
//                         b[pai_nxt[j]] = a[j];
//                     // cout << "party" << idx << "shuffle!\n";
//                 }
//                 ReshareVec(b, (i + 1) % 3);
//                 a = b;
//                 // vector<i64> ttt(n);
//                 // foru(i, 0, n) ttt[i] = enc.revealAll(comms[idx], a[i]);
//                 // IFparty0
//                 // {
//                 //     cout << "after_shuffle_round_1: ";
//                 //     foru(i, 0, n) cout << (int)(ttt[i]) << " \n"[i == n - 1];
//                 // }
//             }
//             return b;
//         };

//         /**
//          * @Method Unshuffle 完整的Unshuffling protocol
//          * @param a 需要Unshuffle的vector<si64>
//          *
//          * @return vector<si64>
//          */
//         auto Unshuffle = [&](vector<si64> a)
//         {
//             vector<si64> b(n);
//             for (i32 i = 2; i >= 0; --i)
//             {
//                 if (idx == i)
//                 {
//                     for (u32 j = 0; j < n; ++j)
//                         b[inv_pai_now[j]] = a[j];
//                     // cout << "party" << idx << "Unshuffle!\n";
//                 }
//                 else if (idx == (i + 2) % 3)
//                 {
//                     for (u32 j = 0; j < n; ++j)
//                         b[inv_pai_nxt[j]] = a[j];
//                     // cout << "party" << idx << "Unshuffle!\n";
//                 }
//                 ReshareVec(b, (i + 1) % 3);
//                 a = b;
//             }
//             return b;
//         };

//         /**
//          * @Method ApplyPerm  Applying a shared-vector permutation
//          * @param rho Secret-shared permutation
//          * @param k apply to vector<si64>
//          *
//          * @return vector<si64>
//          */
//         auto ApplyPerm = [&](vector<si64> rho, vector<si64> k)
//         {
//             vector<si64> pai_rho = Shuffle(rho);
//             vector<si64> pai_k = Shuffle(k);
//             vector<i64> rho_inv_pai(n);
//             foru(i, 0, n) rho_inv_pai[i] = enc.revealAll(comms[idx], pai_rho[i]);
//             vector<si64> rho_k(n);
//             foru(i, 0, n) rho_k[rho_inv_pai[i]] = pai_k[i];
//             return rho_k;
//         };

//         /**
//          * @Method Compose   Composition of two share-vector permutations
//          * @param sigma Secret-shared permutation1
//          * @param rho Secret-shared permutation2
//          *
//          * @return vector<si64> rho o sigma
//          */
//         auto Compose = [&](vector<si64> sigma, vector<si64> rho)
//         {
//             vector<si64> pai_sigma = Shuffle(sigma);
//             vector<i64> sigma_inv_pai(n);
//             foru(i, 0, n) sigma_inv_pai[i] = enc.revealAll(comms[idx], pai_sigma[i]);
//             vector<i64> pai_inv_sigma(n);
//             foru(i, 0, n) pai_inv_sigma[sigma_inv_pai[i]] = i;
//             vector<si64> ld(n);
//             foru(i, 0, n) ld[pai_inv_sigma[i]] = rho[i];
//             vector<si64> rho_sigma = Unshuffle(ld);
//             return rho_sigma;
//         };

//         /**
//          * @Method GenBitPerm  Generating permutation of stable sort for a single
// bit key
//          * @param k Secret-shared bit-wise keys
//          *
//          * @return vector<si64>
//          */
//         auto GenBitPerm = [&](vector<si64> k)
//         {
//             vector<vector<si64>> f(2, vector<si64>(n));
//             foru(i, 0, n)
//             {
//                 f[0][i] = sone - k[i];
//                 f[1][i] = k[i];
//             }
//             vector<vector<si64>> s(2, vector<si64>(n));
//             si64 cnt = szero;
//             foru(j, 0, 2) foru(i, 0, n)
//             {
//                 cnt = cnt + f[j][i];
//                 s[j][i] = cnt;
//             }
//             vector<si64> rho(n);
//             foru(i, 0, n)
//             {
//                 si64 tmp;
//                 eval.asyncMul(rt.noDependencies(), k[i], s[1][i] - s[0][i], tmp).get();
//                 rho[i] = s[0][i] + tmp - sone;
//             }
//             return rho;
//         };

//         /**
//          * @Method GenPerm  Securely Generating a Stable Sorting Permutation
//          * @param k Secret-shared keys.
//          * k[i][j] represents The i-th binary digit of the jth number
//          *
//          * @return vector<si64>
//          * permutation for stable sorting the vector k.
//          */
//         auto GenPerm = [&](vector<vector<si64>> k)
//         {
//             vector<si64> rho, sigma, k_prime;
//             sigma = GenBitPerm(k[0]);
//             // return sigma;
//             // cout << "yeee\n";
//             foru(j, 1, m)
//             {
//                 if (idx == 0)
//                     t.setTimePoint("m = " + to_string(j));
//                 // cout << "x\n";
//                 k_prime = ApplyPerm(sigma, k[j]);
//                 // cout << "y\n";
//                 rho = GenBitPerm(k_prime);
//                 sigma = Compose(sigma, rho);
//             }
//             return sigma;
//         };

//         /**
//          * @Method CheckSort  check the results
//          * @param res permutation for stable sorting
//          * res[i] represents The i-th number's ranking in the original sequence
//          *
//          * @return bool.  Good Sort or Bad Sort.
//          */
//         auto CheckSort = [&](vector<i64> res)
//         {
//             if (idx != 0)
//                 return true;
//             cout << "ranks :\n";
//             foru(i, 0, n) cout << res[i] << " \n"[i == n - 1];
//             vector<i64> a_sorted(n);
//             foru(i, 0, n) a_sorted[res[i]] = a[i];
//             cout << "a sorted: \n";
//             foru(i, 0, n) cout << a_sorted[i] << " \n"[i == n - 1];

//             foru(i, 0, n - 1) if (a_sorted[i] > a_sorted[i + 1])
//             {
//                 cout << "\nBad Sort\n";
//                 return false;
//             };
//             cout << "\nGood Sort!\n";
//             return true;
//         };

//         /* Start */

//         /* Input datas */
//         vector<si64> A(n);
//         IFparty0 t.setTimePoint("start");

//         foru(i, 0, n)
//         {
//             // A[i] = (idx == 0) ? enc.localInt(comms[idx], a[i]) : enc.remoteInt(comms[idx]);
//             if (idx == 0)
//             {
//                 task = enc.localInt(task, a[i], A[i]);
//             }
//             else
//             {
//                 task = enc.remoteInt(task, A[i]);
//             }
//         }
//         task.get();

//         // auto x1 = A[0].mData[0], x2 = A[0].mData[1];
//         // cout << "shares[" << idx << "] = " << (int)x1 << ' ' << (int)x2 << endl;

//         vector<vector<si64>> k(m, vector<si64>(n));
//         foru(i, 0, m) foru(j, 0, n)
//         {
//             // k[i][j] = (idx == 0) ? enc.localInt(comms[idx], k_plain[i][j]) : enc.remoteInt(comms[idx]);
//             if (idx == 0)
//             {
//                 task = enc.localInt(task, k_plain[i][j], k[i][j]);
//             }
//             else
//             {
//                 task = enc.remoteInt(task, k[i][j]);
//             }
//         }
//         task.get();

//         // vector<i64> res;
//         // foru(i, 0, m) foru(j, 0, n)
//         //     res.emplace_back(enc.revealAll(comms[idx], k[i][j]));
//         // if (idx == 0)
//         //     for (auto i : res)S
//         //         cout << i << ' ';
//         /*---------------------------------reshare--------------------------------*/
//         // for (auto A_ : A)
//         //     reshare(A_, 0);
//         // reshare(A[0], 0);
//         /*---------------------------------shuffle--------------------------------*/
//         // vector<si64> tmp = Shuffle(A);
//         // vector<i64> ttt(n);
//         // foru(i, 0, n) ttt[i] = enc.revealAll(comms[idx], tmp[i]);
//         // IFparty0
//         // {
//         //     cout << "after_shuffle: ";
//         //     foru(i, 0, n) cout << (int)(ttt[i]) << " \n"[i == n - 1];
//         // }
//         /*--------------------------------unshuffle--------------------------------*/
//         // vector<si64> tmp = Unshuffle(A);
//         // // tmp = Unshuffle(Shuffle(A));
//         // vector<i64> ttt(n);
//         // foru(i, 0, n) ttt[i] = enc.revealAll(comms[idx], tmp[i]);
//         // IFparty0
//         // {
//         //     cout << "after_unshuffle: \n";
//         //     foru(i, 0, n) cout << (int)(ttt[i]) << " \n"[i == n - 1];
//         // }
//         /*----------------------------------ApplyPerm------------------------------*/
//         // vector<i64> x2 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
//         // vector<i64> x1 = {3, 8, 7, 6, 5, 4, 9, 2, 1, 0};
//         // vector<si64> xx1(n), xx2(n);
//         // IFparty0
//         // {S
//         //     foru(i, 0, n) xx1[i] = enc.localInt(comms[idx], x1[i]);
//         //     foru(i, 0, n) xx2[i] = enc.localInt(comms[idx], x2[i]);
//         // }
//         // else
//         // {
//         //     foru(i, 0, n) xx1[i] = enc.remoteInt(comms[idx]);
//         //     foru(i, 0, n) xx2[i] = enc.remoteInt(comms[idx]);
//         // }
//         // vector<si64> tttt = ApplyPerm(xx1, xx2);
//         // vector<i64> ttt(n);
//         // foru(i, 0, n) ttt[i] = enc.revealAll(comms[idx], tttt[i]);
//         // foru(i, 0, n) cout << ttt[i] << " \n"[i == n - 1];
//         /*--------------------------------GenBitPerm------------------------------*/
//         // vector<i64> kk = {1, 1, 1, 0, 0, 1, 0, 0, 1, 1};
//         // vector<si64> k(n);

//         // foru(i, 0, n) k[i] = (idx == 0) ? enc.localInt(comms[idx], kk[i]) : enc.remoteInt(comms[idx]);

//         // vector<si64> rho = GenBitPerm(k);
//         // vector<i64> res(n);
//         // foru(i, 0, n) res[i] = enc.revealAll(comms[idx], rho[i]);
//         // cout << "rho :\n";
//         // foru(i, 0, n) cout << res[i] << " \n"[i == n - 1];
//         /*---------------------------------GenPerm-------------------------------*/
//         IFparty0 t.setTimePoint("sort");
//         // vector<si64> sigma = GenPerm(k);
//         // IFparty0 t.setTimePoint("finish");
//         // vector<i64> res(n);
//         // foru(i, 0, n) res[i] = enc.revealAll(comms[idx], sigma[i]);
//         // CheckSort(res);

//         /*---------------------------------mult test-----------------------------*/
//         // vector<si64> C(n);
//         // IFparty0
//         //     t.setTimePoint("eval");
//         // foru(i, 0, n) task = eval.asyncMul(task, A[i], A[i], C[i]);
//         // task.get();
//         // vector<i64> c(n);
//         // IFparty0
//         //     t.setTimePoint("reveal_3");
//         // foru(i, 0, n) c[i] = enc.revealAll(comms[idx], C[i]);
//         // IFparty0
//         // {
//         //     cout << "a^2 : ";
//         //     foru(i, 0, n) cout << c[i] << " \n"[i == n - 1];
//         // }
//     };

//     auto t0 = std::thread(routine, 0);
//     auto t1 = std::thread(routine, 1);
//     auto t2 = std::thread(routine, 2);

//     t0.join();
//     t1.join();
//     t2.join();

//     auto comm0 = (comms[0].mNext.getTotalDataSent() + comms[0].mNext.getTotalDataSent());
//     auto comm1 = (comms[1].mNext.getTotalDataSent() + comms[1].mNext.getTotalDataSent());
//     auto comm2 = (comms[2].mNext.getTotalDataSent() + comms[2].mNext.getTotalDataSent());
//     std::cout << "\nn = " << n << "   " << comm0 + comm1 + comm2 << "\n"
//               << t << std::endl;

//     if (failed)
//         throw std::runtime_error(LOCATION);

//     return 0;
// }

i64 Input_test(u64 n)
{
    IOService ios;
    Session s01(ios, "127.0.0.1", SessionMode::Server, "01");
    Session s10(ios, "127.0.0.1", SessionMode::Client, "01");
    Session s02(ios, "127.0.0.1", SessionMode::Server, "02");
    Session s20(ios, "127.0.0.1", SessionMode::Client, "02");
    Session s12(ios, "127.0.0.1", SessionMode::Server, "12");
    Session s21(ios, "127.0.0.1", SessionMode::Client, "12");

    Channel chl01 = s01.addChannel("c");
    Channel chl10 = s10.addChannel("c");
    Channel chl02 = s02.addChannel("c");
    Channel chl20 = s20.addChannel("c");
    Channel chl12 = s12.addChannel("c");
    Channel chl21 = s21.addChannel("c");

    CommPkg comms[3];
    comms[0] = {chl02, chl01};
    comms[1] = {chl10, chl12};
    comms[2] = {chl21, chl20};

    bool failed = false;

    Timer t;
    u32 MOD = 10;
    // i64Matrix a(n, 1);
    vector<i64> a(n);
    PRNG prng(ZeroBlock);
    foru(i, 0, n) a[i] = abs(prng.get<i64>() % MOD);
    cout << "a :\n";
    foru(i, 0, n) if (i % 1000 == 0) cout << a[i] << " ";
    cout << endl;

    auto routine = [&](int idx)
    {
        i64Matrix res(n, 1);
        sbMatrix RES(n, 64);
        /*--------------Preparations---------------------------------------------------*/
        PRNG prng;
        Sh3Runtime rt(idx, comms[idx]);
        Sh3Encryptor enc;
        Sh3BinaryEvaluator eval;
        Sh3Task task = rt.noDependencies();
        BetaLibrary lib;
        BetaCircuit *cir_add = lib.int_int_add(64, 64, 64);
        BetaCircuit *cir_mult = lib.int_int_mult(64, 64, 64);
        cir_add->levelByAndDepth();
        cir_mult->levelByAndDepth();
        enc.init(idx, comms[idx], sysRandomSeed());
        // eval.init(idx, comms[idx], sysRandomSeed());

        // sbMatrix A(n, 64);
        vector<sb64> A(n);
        if (idx == 0)
            t.setTimePoint("start");

        // task = idx == 0 ? enc.localBinMatrix(rt.noDependencies(), a, A) : enc.remoteBinMatrix(rt.noDependencies(), A);
        foru(i, 0, n)
        {
            task = idx == 0 ? enc.localBinary(rt.noDependencies(), a[i], A[i]) : enc.remoteBinary(rt.noDependencies(), A[i]);
        }
        task.get();
        if (idx == 0)
            t.setTimePoint("input");

        // enc.revealAll(rt.noDependencies(), A, res).get();

        // if (idx == 0)
        // {
        //     cout << "c :\n";
        //     foru(i, 0, n) if (i % 1000 == 0) cout << res(i) << " ";
        //     cout << endl;
        //     t.setTimePoint("revealAll");
        // }

        // eval.asyncEvaluate(rt.noDependencies(), cir_add, enc.mShareGen, {&A, &A}, {&RES}).get();
        // if (idx == 0)
        //     t.setTimePoint("add");

        // enc.revealAll(rt.noDependencies(), RES, res).get();
        // if (idx == 0)
        // {
        //     cout << "c_add :\n";
        //     foru(i, 0, n) if (i % 1000 == 0) cout << res(i) << " ";
        //     cout << endl;
        //     t.setTimePoint("revealAll");
        // }

        // eval.asyncEvaluate(rt.noDependencies(), cir_mult, enc.mShareGen, {&A, &A}, {&RES}).get();
        // if (idx == 0)
        //     t.setTimePoint("mult");

        // enc.revealAll(rt.noDependencies(), RES, res).get();
        // if (idx == 0)
        // {
        //     cout << "c_mult :\n";
        //     foru(i, 0, n) if (i % 1000 == 0) cout << res(i) << " ";
        //     cout << endl;
        //     t.setTimePoint("revealAll");
        // }
    };

    auto t0 = std::thread(routine, 0);
    auto t1 = std::thread(routine, 1);
    auto t2 = std::thread(routine, 2);

    t0.join();
    t1.join();
    t2.join();

    auto comm0 = (comms[0].mNext.getTotalDataSent() + comms[0].mNext.getTotalDataSent());
    auto comm1 = (comms[1].mNext.getTotalDataSent() + comms[1].mNext.getTotalDataSent());
    auto comm2 = (comms[2].mNext.getTotalDataSent() + comms[2].mNext.getTotalDataSent());
    std::cout << "\nn = " << n << "   " << comm0 + comm1 + comm2 << "\n"
              << t << std::endl;

    if (failed)
        throw std::runtime_error(LOCATION);

    return 0;
}

signed
main()
{
    Sh3_Int_Vector_test(100);
    // Input_test(10000);
    return 0;
}