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
    i64Matrix a(n, 1);
    // vector<i64> a(n);
    PRNG prng(ZeroBlock);
    foru(i, 0, n) a(i) = abs(prng.get<i64>() % MOD);
    cout << "a :\n";
    foru(i, 0, n) if (i < 10 || i % 1000 == 0) cout << a(i) << " ";
    cout << endl;
    i64 globalres = 0;
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

        sbMatrix A(n, 64);
        if (idx == 0)
            t.setTimePoint("start");

        task = idx == 0 ? enc.localBinMatrix(rt.noDependencies(), a, A) : enc.remoteBinMatrix(rt.noDependencies(), A);
        task.get();
        if (idx == 0)
            t.setTimePoint("input");

        auto x2 = A[1];
        cout << "\nidx = " << idx << endl;
        foru(i, 0, n) cout << x2(i) << ' ';
        globalres ^= x2(0);
        cout << endl;

        enc.revealAll(rt.noDependencies(), A, res).get();
        if (idx == 0)
        {
            cout << "c :\n";
            foru(i, 0, n) if (i < 10 || i % 1000 == 0) cout << res(i) << " ";
            cout << endl;
            t.setTimePoint("revealAll");
        }

        eval.asyncEvaluate(rt.noDependencies(), cir_add, enc.mShareGen, {&A, &A}, {&RES}).get();
        if (idx == 0)
            t.setTimePoint("add");
        enc.revealAll(task, RES, res).get();
        if (idx == 0)
        {
            cout << "c_add :\n";
            foru(i, 0, n) if (i < 10 || i % 1000 == 0) cout << res(i) << " ";
            cout << endl;
            t.setTimePoint("revealAll");
        }

        eval.asyncEvaluate(task, cir_mult, enc.mShareGen, {&A, &A}, {&RES}).get();
        if (idx == 0)
            t.setTimePoint("mult");
        enc.revealAll(task, RES, res).get();
        if (idx == 0)
        {
            cout << "c_mult :\n";
            foru(i, 0, n) if (i < 10 || i % 1000 == 0) cout << res(i) << " ";
            cout << endl;
            t.setTimePoint("revealAll");
        }

        auto A2 = A;
        foru(i, 0, n)
        {
            A2[0](i) = A[0]((i + 1) % n);
            A2[1](i) = A[1]((i + 1) % n);
        }

        // x2 = A2[1];
        // cout << "\nidx = " << idx << endl;
        // foru(i, 0, n) cout << x2(i) << ' ';
        // cout << endl;

        if (idx == 0)
            t.setTimePoint("swap");
        enc.revealAll(rt.noDependencies(), A2, res).get();
        if (idx == 0)
        {
            cout << "c_swap :\n";
            foru(i, 0, n) if (i < 10 || i % 1000 == 0) cout << res(i) << " ";
            cout << endl;
            t.setTimePoint("revealAll");
        }
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
    cout << "globalres: \n"
         << globalres << endl;
    std::cout << "\nn = " << n << "   " << comm0 + comm1 + comm2 << "\n"
              << t << std::endl;

    if (failed)
        throw std::runtime_error(LOCATION);

    return 0;
}

signed
main()
{
    Input_test(10);
    return 0;
}