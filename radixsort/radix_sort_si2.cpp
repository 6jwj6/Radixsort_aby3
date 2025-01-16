#pragma GCC optimize(3, "Ofast", "inline")
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

i64 Sh3_Int_Vector_test(u64 n)
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
    u32 MOD = 10000;
    i64Matrix a(n, 1);
    // PRNG prng(ZeroBlock);
    PRNG prng(std::array<uint8_t, 16>{std::random_device{}(), std::random_device{}(), std::random_device{}(), std::random_device{}(),
                                      std::random_device{}(), std::random_device{}(), std::random_device{}(), std::random_device{}(),
                                      std::random_device{}(), std::random_device{}(), std::random_device{}(), std::random_device{}(),
                                      std::random_device{}(), std::random_device{}(), std::random_device{}(), std::random_device{}()});

    foru(i, 0, n)
        a(i) = abs(prng.get<i64>() % MOD);

    cout << "a :\n";
    foru(i, 0, n) cout << a(i) << ' ';
    cout << endl;

    int m = 0;
    foru(i, 0, n) m = max(m, (int)ceil(log10(a(i) + 1) / log10(2)));
    cout << "m = " << m << endl;
    vector<i64Matrix> k_plain(m, i64Matrix(n, 1));
    auto aa = a;
    foru(i, 0, n) foru(j, 0, m)
    {
        k_plain[j](i) = aa(i) & 1;
        aa(i) >>= 1;
    }
    // foru(i, 0, m) foru(j, 0, n) cout << k_plain[i](j) << " \n"[j == n - 1];
    i64Matrix ione(n, 1), izero(n, 1);
    foru(i, 0, n) ione(i) = 1, izero(i) = 0;

    auto routine = [&](int idx)
    {
        PRNG prng(ZeroBlock);
        vector<u32> pai_now(n), pai_nxt(n), inv_pai_now(n), inv_pai_nxt(n);
        std::iota(pai_now.begin(), pai_now.end(), 0);
        std::random_shuffle(pai_now.begin(), pai_now.end(), prng);
        comms[idx].mPrev.asyncSendCopy(pai_now);
        comms[idx].mNext.recv(pai_nxt);
        foru(i, 0, n) inv_pai_now[pai_now[i]] = inv_pai_nxt[pai_nxt[i]] = i;
        /*--------------Preparations---------------------------------------------------*/
        Sh3Runtime rt(idx, comms[idx]);
        Sh3Encryptor enc;
        Sh3Evaluator eval;
        Sh3Task task = rt.noDependencies();
        enc.init(idx, comms[idx], sysRandomSeed());
        eval.init(idx, comms[idx], sysRandomSeed());

        si64 ssone, sszero;
        ssone = idx == 0 ? enc.localInt(comms[idx], 1) : enc.remoteInt(comms[idx]);
        sszero = idx == 0 ? enc.localInt(comms[idx], 0) : enc.remoteInt(comms[idx]);

        /**
         * @Method Random_pai 生成随机的 pai, 即 pai_now , pai_next
         *
         * @return void
         */
        auto Random_pai = [&]() -> void
        {
            // std::iota(pai_now.begin(), pai_now.end(), 0);
            std::random_shuffle(pai_now.begin(), pai_now.end(), prng);
            comms[idx].mPrev.asyncSendCopy(pai_now);
            comms[idx].mNext.recv(pai_nxt);
            foru(i, 0, n) inv_pai_now[pai_now[i]] = inv_pai_nxt[pai_nxt[i]] = i;
        };

        /**
         * @Method ReshareVec Party i-1 和 i+1, reshare vector_x to Party i
         * @param X 需要reshare的 si64Matrix
         * @param i reshare的接收方
         * @return void
         */
        auto ReshareVec = [&](si64Matrix &X, u32 i) -> void
        {
            u32 pre = (i + 2) % 3, nxt = (i + 1) % 3;
            si64Matrix tmp(X.size(), 1);
            enc.remoteIntMatrix(rt.noDependencies(), tmp).get(); // tmp = 0
            if (idx == nxt || idx == pre)
            {
                X[0] = X[0] + tmp[0];
                X[1] = X[1] + tmp[1];
            }
            if (idx == i)
            {
                comms[i].mPrev.recv(X.mShares[1].data(), X.mShares[1].size());
                comms[i].mNext.recv(X.mShares[0].data(), X.mShares[0].size());
            }
            else if (idx == nxt)
            {
                comms[nxt].mPrev.asyncSendCopy(X.mShares[1].data(), X.mShares[1].size());
            }
            else if (idx == pre)
            {
                comms[pre].mNext.asyncSendCopy(X.mShares[0].data(), X.mShares[0].size());
            }
        };

        /**
         * @Method Shuffle 完整的Shuffling protocol
         * @param a 需要shuffle的 si64matrix
         *
         * @return si64matrix
         */
        auto Shuffle = [&](si64Matrix a)
        {
            si64Matrix b(n, 1);
            for (u8 i = 0; i <= 2; ++i)
            {
                if (idx == i)
                {
                    for (u32 j = 0; j < n; ++j)
                    {
                        b[0](pai_now[j]) = a[0](j);
                        b[1](pai_now[j]) = a[1](j);
                    }
                }
                else if (idx == (i + 2) % 3)
                {
                    for (u32 j = 0; j < n; ++j)
                    {
                        b[0](pai_nxt[j]) = a[0](j);
                        b[1](pai_nxt[j]) = a[1](j);
                    }
                }

                ReshareVec(b, (i + 1) % 3);
                a = b;
            }
            return b;
        };

        /**
         * @Method Unshuffle 完整的Unshuffling protocol
         * @param a 需要Unshuffle的vector<si64>
         *
         * @return si64matrix
         */
        auto Unshuffle = [&](si64Matrix a)
        {
            si64Matrix b(n, 1);
            for (i32 i = 2; i >= 0; --i)
            {
                if (idx == i)
                {
                    for (u32 j = 0; j < n; ++j)
                    {
                        b[0](inv_pai_now[j]) = a[0](j);
                        b[1](inv_pai_now[j]) = a[1](j);
                    }
                }
                else if (idx == (i + 2) % 3)
                {
                    for (u32 j = 0; j < n; ++j)
                    {
                        b[0](inv_pai_nxt[j]) = a[0](j);
                        b[1](inv_pai_nxt[j]) = a[1](j);
                    }
                }
                ReshareVec(b, (i + 1) % 3);
                a = b;
            }
            return b;
        };

        /**
         * @Method ApplyPerm  Applying a shared-vector permutation
         * @param rho Secret-shared permutation
         * @param k apply to si64matrix
         *
         * @return si64matrix
         */
        auto ApplyPerm = [&](si64Matrix rho, si64Matrix k)
        {
            Random_pai();
            // if (idx == 0)
            //     t.setTimePoint("m random_pai= " + to_string(idx));
            auto pai_rho = Shuffle(rho);
            // if (idx == 0)
            //     t.setTimePoint("m shuffle1= " + to_string(idx));
            auto pai_k = Shuffle(k);
            // if (idx == 0)
            //     t.setTimePoint("m shuffle2= " + to_string(idx));
            i64Matrix rho_inv_pai(n, 1);
            // if (idx == 0)
            //     t.setTimePoint("m before reveal= " + to_string(idx));
            enc.revealAll(rt.noDependencies(), pai_rho, rho_inv_pai).get();
            // if (idx == 0)
            //     t.setTimePoint("m reveal= " + to_string(idx));
            si64Matrix rho_k(n, 1);
            foru(i, 0, n)
            {
                rho_k[0](rho_inv_pai(i)) = pai_k[0](i);
                rho_k[1](rho_inv_pai(i)) = pai_k[1](i);
            }
            return rho_k;
        };

        /**
         * @Method Compose   Composition of two share-vector permutations
         *
         * @param sigma Secret-shared permutation1
         * @param rho Secret-shared permutation2
         *
         * @return si64matrix rho o sigma
         */
        auto Compose = [&](si64Matrix sigma, si64Matrix rho)
        {
            Random_pai();
            auto pai_sigma = Shuffle(sigma);
            i64Matrix sigma_inv_pai(n, 1);

            enc.revealAll(rt.noDependencies(), pai_sigma, sigma_inv_pai).get();
            i64Matrix pai_inv_sigma(n, 1);
            foru(i, 0, n) pai_inv_sigma(sigma_inv_pai(i)) = i;

            si64Matrix ld(n, 1);
            foru(i, 0, n)
            {
                ld[0](pai_inv_sigma(i)) = rho[0](i);
                ld[1](pai_inv_sigma(i)) = rho[1](i);
            }
            auto rho_sigma = Unshuffle(ld);

            return rho_sigma;
        };

        /**
         * @Method GenBitPerm  Generating permutation of stable sort for a single
bit key
         * @param k Secret-shared bit-wise keys
         *
         * @return vector<si64>
         */
        auto GenBitPerm = [&](si64Matrix k)
        {
            vector<si64Matrix> f(2, si64Matrix(n, 1));
            foru(i, 0, n)
            {
                f[0][0](i) = ssone[0] - k[0](i);
                f[0][1](i) = ssone[1] - k[1](i);
                f[1][0](i) = k[0](i);
                f[1][1](i) = k[1](i);
            }

            vector<si64Matrix> s(2, si64Matrix(n, 1));
            si64 cnt = sszero;
            foru(j, 0, 2) foru(i, 0, n)
            {
                cnt[0] = cnt[0] + f[j][0](i);
                cnt[1] = cnt[1] + f[j][1](i);
                s[j][0](i) = cnt[0];
                s[j][1](i) = cnt[1];
            }

            si64Matrix rho(n, 1), Tmp(n, 1), mi(n, 1);
            foru(i, 0, n)
            {
                si64 tmp = (si64)s[1](i) - (si64)s[0](i);
                mi[0](i) = tmp[0];
                mi[1](i) = tmp[1];
            }

            eval.asyncEleWiseMul(rt.noDependencies(), k, mi, Tmp).get();
            foru(i, 0, n)
            {
                rho[0](i) = s[0][0](i) + Tmp[0](i) - ssone[0];
                rho[1](i) = s[0][1](i) + Tmp[1](i) - ssone[1];
            }
            return rho;
        };

        /**
         * @Method GenPerm  Securely Generating a Stable Sorting Permutation
         * @param k Secret-shared keys.
         * k[i][j] represents The i-th binary digit of the jth number
         *
         * @return si64matrix
         * permutation for stable sorting the vector k.
         */
        auto GenPerm = [&](vector<si64Matrix> k)
        {
            si64Matrix rho, sigma, k_prime;
            sigma = GenBitPerm(k[0]);
            if (idx == 0)
                t.setTimePoint("mGenBitPerm = " + to_string(0));
            i64Matrix res(n, 1);
            foru(j, 1, m)
            {
                k_prime = ApplyPerm(sigma, k[j]);
                if (idx == 0)
                    t.setTimePoint("mApplyPerm = " + to_string(j));

                rho = GenBitPerm(k_prime);
                if (idx == 0)
                    t.setTimePoint("mGenBitPerm = " + to_string(j));

                sigma = Compose(sigma, rho);
                if (idx == 0)
                    t.setTimePoint("mCompose = " + to_string(j));
            }
            return sigma;
        };

        /**
         * @Method CheckSort  check the results
         * @param res permutation for stable sorting
         * res[i] represents The i-th number's ranking in the original sequence
         * @return bool.  Good Sort or Bad Sort.
         */
        auto CheckSort = [&](i64Matrix res)
        {
            if (idx != 0)
                return true;
            cout << "\nranks :\n";
            foru(i, 0, n) cout << res(i) << " \n"[i == n - 1];
            i64Matrix a_sorted(n, 1);
            foru(i, 0, n) a_sorted(res(i)) = a(i);
            cout << "\na sorted: \n";
            foru(i, 0, n) cout << a_sorted(i) << " \n"[i == n - 1];

            foru(i, 0, n - 1) if (a_sorted(i) > a_sorted(i + 1))
            {
                cout << "\nBad Sort\n";
                return false;
            };
            cout << "\nGood Sort!\n";
            return true;
        };

        /* Start */

        /*----------------------------- Input datas -------------------------------*/
        si64Matrix A(n, 1);
        IFparty0 t.setTimePoint("start");
        task = idx == 0 ? enc.localIntMatrix(rt.noDependencies(), a, A) : enc.remoteIntMatrix(rt.noDependencies(), A);
        vector<si64Matrix> k(m, si64Matrix(n, 1));
        foru(i, 0, m)
            task = idx == 0 ? enc.localIntMatrix(rt.noDependencies(), k_plain[i], k[i]) : enc.remoteIntMatrix(rt.noDependencies(), k[i]);
        task.get();
        IFparty0 t.setTimePoint("input");

        comms[idx].mNext.resetStats();
        comms[idx].mPrev.resetStats();

        /*---------------------------------GenPerm-------------------------------*/
        si64Matrix sigma = GenPerm(k);
        IFparty0 t.setTimePoint("sort");
        i64Matrix res(n, 1);
        enc.revealAll(rt.noDependencies(), sigma, res).get();
        CheckSort(res);
    };

    auto t0 = std::thread(routine, 0);
    auto t1 = std::thread(routine, 1);
    auto t2 = std::thread(routine, 2);

    t0.join();
    t1.join();
    t2.join();

    auto comm0p = comms[0].mPrev.getTotalDataSent() + comms[0].mPrev.getTotalDataRecv();
    auto comm1p = comms[1].mPrev.getTotalDataSent() + comms[1].mPrev.getTotalDataRecv();
    auto comm2p = comms[2].mPrev.getTotalDataSent() + comms[2].mPrev.getTotalDataRecv();
    auto comm0n = comms[0].mNext.getTotalDataSent() + comms[0].mNext.getTotalDataRecv();
    auto comm1n = comms[1].mNext.getTotalDataSent() + comms[1].mNext.getTotalDataRecv();
    auto comm2n = comms[2].mNext.getTotalDataSent() + comms[2].mNext.getTotalDataRecv();
    std::cout << "\nn = " << n << "   m = " << m << "   " << comm0p + comm1p + comm2p + comm0n + comm1n + comm2n << "\n"
              << comm0p << "  " << comm1p << "  " << comm2p << "  " << comm0n << "  " << comm1n << "  " << comm2n << "\n"
              << t << std::endl;

    if (failed)
        throw std::runtime_error(LOCATION);

    return 0;
}

signed main()
{
    Sh3_Int_Vector_test(10000);
    return 0;
}

/*-----------------------------------test inv_pai-----------------------------*/
// vector<u32> test(n), test1(n), test2(n);
// std::iota(test.begin(), test.end(), 0);
// foru(i, 0, n) test1[pai_nxt[i]] = test[i];
// foru(i, 0, n) test2[inv_pai_nxt[i]] = test1[i];
// cout << "test:\n";
// foru(i, 0, n) cout << test[i] << " \n"[i == n - 1];
// cout << "test1:\n";
// foru(i, 0, n) cout << test1[i] << " \n"[i == n - 1];
// cout << "test2:\n";
// foru(i, 0, n) cout << test2[i] << " \n"[i == n - 1];
/*---------------------------------reshare--------------------------------*/
// ReshareVec(A, 0);
// i64Matrix ttt1(n, 1);
// ttt1 = enc.revealAll(comms[idx], A);
// IFparty0
// {
//     cout << "before_shuffle: ";
//     foru(i, 0, n) cout << (int)(ttt1(i)) << " \n"[i == n - 1];
// }
/*---------------------------------shuffle--------------------------------*/
// si64Matrix tmp = Shuffle(A);
// i64Matrix ttt(n, 1);
// ttt = enc.revealAll(comms[idx], A);
// IFparty0
// {
//     cout << "before_shuffle: ";
//     foru(i, 0, n) cout << (int)(ttt(i)) << " \n"[i == n - 1];
// }
// // vector<i64> ttt(n);
// // foru(i, 0, n) ttt[i] = enc.revealAll(comms[idx], tmp[i]);
// ttt = enc.revealAll(comms[idx], tmp);
// IFparty0
// {
//     cout << "after_shuffle: ";
//     foru(i, 0, n) cout << (int)(ttt(i)) << " \n"[i == n - 1];
// }
/*--------------------------------unshuffle--------------------------------*/
// si64Matrix tmp = Unshuffle(A);
// // tmp = Unshuffle(Shuffle(A));
// i64Matrix ttt(n, 1);
// ttt = enc.revealAll(comms[idx], tmp);
// IFparty0
// {
//     cout << "after_unshuffle: \n";
//     foru(i, 0, n) cout << (int)(ttt(i)) << " \n"[i == n - 1];
// }
/*----------------------------------ApplyPerm------------------------------*/
// i64Matrix x2(10, 1);
// foru(i, 0, 10) x2(i) = i;
// i64Matrix x1(10, 1);
// vector<int> vec = {3, 8, 7, 6, 5, 4, 9, 2, 1, 0};
// foru(i, 0, 10) x1(i) = vec[i];
// si64Matrix xx1(10, 1), xx2(10, 1);
// IFparty0
// {
//     // foru(i, 0, 10) xx1[i] = enc.localInt(comms[idx], x1[i]);
//     // foru(i, 0, 10) xx2[i] = enc.localInt(comms[idx], x2[i]);
//     enc.localIntMatrix(rt.noDependencies(), x1, xx1).get();
//     enc.localIntMatrix(rt.noDependencies(), x2, xx2).get();
// }
// else
// {
//     enc.remoteIntMatrix(rt.noDependencies(), xx1).get();
//     enc.remoteIntMatrix(rt.noDependencies(), xx2).get();
// }
// auto tttt = ApplyPerm(xx1, xx2);
// i64Matrix ttt(n, 1);
// // foru(i, 0, n) ttt[i] = enc.revealAll(comms[idx], tttt[i]);
// ttt = enc.revealAll(comms[idx], tttt);
// cout << "ttt(i) \n";
// foru(i, 0, n) cout << ttt(i) << " \n"[i == n - 1];
/*--------------------------------GenBitPerm------------------------------*/
// n = 10;
// i64Matrix kk(n, 1);
// vector<int> vec = {1, 1, 1, 0, 0, 1, 0, 0, 1, 1};
// si64Matrix k_(n, 1);
// foru(i, 0, n) kk(i) = vec[i];
// // foru(i, 0, n) k[i] = (idx == 0) ? enc.localInt(comms[idx], kk[i]) : enc.remoteInt(comms[idx]);
// task = (idx == 0) ? enc.localIntMatrix(rt.noDependencies(), kk, k_) : enc.remoteIntMatrix(rt.noDependencies(), k_);
// task.get();
// auto rho = GenBitPerm(k_);
// i64Matrix ress(n, 1);
// ress = enc.revealAll(comms[idx], rho);
// cout << "rho :\n";
// foru(i, 0, n) cout << ress(i) << " \n"[i == n - 1];
/*---------------------------------mult test-----------------------------*/
// vector<si64> C(n);
// IFparty0
//     t.setTimePoint("eval");
// foru(i, 0, n) task = eval.asyncMul(task, A[i], A[i], C[i]);
// task.get();
// vector<i64> c(n);
// IFparty0
//     t.setTimePoint("reveal_3");
// foru(i, 0, n) c[i] = enc.revealAll(comms[idx], C[i]);
// IFparty0
// {
//     cout << "a^2 : \n";
//     foru(i, 0, n) cout << c[i] << " \n"[i == n - 1];
// }
/*--------------------------si64matrix mult test-------------------------*/
// i64Matrix xx(n, n), yy(n, n);
// si64Matrix XX(n, n), YY(n, n);
// foru(i, 0, n) xx(i, i) = a[i];
// if (idx == 0)
//     enc.localIntMatrix(rt.noDependencies(), xx, XX).get();
// else
//     enc.remoteIntMatrix(rt.noDependencies(), XX).get();
// enc.revealAll(rt.noDependencies(), XX, yy).get();
// if (idx == 0)
//     cout << "yy : \n"
//          << yy << endl;
// if (idx == 0)
// {
//     auto MXX0 = XX.mShares[0];
//     cout << "MXX0 :\n"
//          << MXX0 << endl;
//     cout << "MXX0(0) MMX0(1):\n"
//          << MXX0(0) << ' ' << MXX0(1) << endl;
//     auto MXX00 = MXX0 * MXX0;
//     i64 tem0 = MXX0(0) * MXX0(0), tem1 = MXX0(0) * MXX0(1);
//     cout << "tem0, tem1 = " << tem0 << ' ' << tem1 << endl;
//     cout << "MXX00:\n"
//          << MXX00 << endl;
// }
// // auto MXX1 = XX.mShares[1];
// // auto XX0 = XX[0];
// // auto XX1 = XX[1];
// // if (MXX0 == XX0)
// //     cout << "equal0!\n";
// // if (MXX1 == XX1)
// //     cout << "equal1!\n";

// task.get();
// // if (idx == 0)
// // {
// cout << "YY = \n";
// cout << YY[0] << endl;
// cout << YY[1] << endl;
// // }
// task = enc.revealAll(task, YY, yy);
// task.get();
// if (idx == 0)
//     cout << "yy : \n"
//          << yy << endl;