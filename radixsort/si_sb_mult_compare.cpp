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

i64 random_perm_test(u64 n)
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
    PRNG prng(ZeroBlock);
    foru(i, 0, n)
        a(i) = abs(prng.get<i64>() % MOD);

    cout << "a :\n";
    foru(i, 0, n) cout << a(i) << ' ';
    cout << endl;
    i64 count = 0;
    auto routine = [&](int idx)
    {
        /*--------------Preparations---------------------------------------------------*/
        PRNG prng;
        Sh3Runtime rt(idx, comms[idx]);
        Sh3Encryptor enc;
        Sh3Evaluator eval;
        Sh3Task task = rt.noDependencies();
        enc.init(idx, comms[idx], sysRandomSeed());
        eval.init(idx, comms[idx], sysRandomSeed());
        /* Input datas */
        si64Matrix A(n, 1);
        IFparty0 t.setTimePoint("start");

        idx == 0 ? enc.localIntMatrix(comms[idx], a, A) : enc.remoteIntMatrix(comms[idx], A);
        t.setTimePoint("input" + to_string(idx));

        /*---------------------------------random_perm--------------------------------*/
        foru(i, 0, n)
        {
            si64 tmp;
            eval.asyncMul(rt.noDependencies(), A(i), A(i), tmp).get();
        }
        t.setTimePoint("si_mult" + to_string(idx));
        i64Matrix ttt1(n, 1);
        ttt1 = enc.revealAll(comms[idx], A);
        IFparty0
        {
            cout << "reshared_A:\n";
            foru(i, 0, n) cout << ttt1(i) << " \n"[i == n - 1];
        }
        t.setTimePoint("revealAll" + to_string(idx));
        //--------------------- sb单个乘法 test-------------------------//
        Sh3BinaryEvaluator evalb;
        BetaLibrary lib;
        BetaCircuit *cir_add = lib.int_int_add(64, 64, 64);
        BetaCircuit *cir_mult = lib.int_int_mult(64, 64, 64);
        cir_add->levelByAndDepth();
        cir_mult->levelByAndDepth();
        i64Matrix u(1, 1), rr(1, 1);
        sbMatrix su(1, 64), x(1, 64);
        u(0) = 2;
        task = idx == 0 ? enc.localBinMatrix(rt.noDependencies(), u, su) : enc.remoteBinMatrix(rt.noDependencies(), su);
        task.get();
        t.setTimePoint("input" + to_string(idx));

        foru(i, 0, 100) evalb.asyncEvaluate(rt.noDependencies(), cir_mult, enc.mShareGen, {&su, &su}, {&x}).get();
        t.setTimePoint("sb_mult" + to_string(idx));

        enc.revealAll(rt.noDependencies(), su, rr).get();
        t.setTimePoint("revealAll" + to_string(idx));

        if (idx == 0)
            cout << "rr = \n"
                 << rr(0) << endl;

        //----------------------sb整个矩阵乘法------------------------------//
        i64Matrix b(n, 1), res(n, 1);
        foru(i, 0, n) b(i) = i + 1;
        sbMatrix B(n, 64);
        task = idx == 0 ? enc.localBinMatrix(rt.noDependencies(), b, B) : enc.remoteBinMatrix(rt.noDependencies(), B);
        task.get();
        t.setTimePoint("input" + to_string(idx));

        enc.revealAll(rt.noDependencies(), B, res).get();
        t.setTimePoint("revealAll" + to_string(idx));
        if (idx == 0)
        {
            cout << "sb_reveal :\n";
            foru(i, 0, n) cout << res(i) << " ";
            cout << endl;
        }

        evalb.asyncEvaluate(rt.noDependencies(), cir_mult, enc.mShareGen, {&B, &B}, {&B}).get();
        t.setTimePoint("sbmatrix_mult" + to_string(idx));

        enc.revealAll(rt.noDependencies(), B, res).get();
        t.setTimePoint("revealAll" + to_string(idx));

        if (idx == 0)
        {
            cout << "sb_reveal :\n";
            foru(i, 0, n) cout << res(i) << " ";
            cout << endl;
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
    cout << "count = " << count << endl;
    std::cout << "\nn = " << n << "   " << comm0 + comm1 + comm2 << "\n"
              << t << std::endl;

    if (failed)
        throw std::runtime_error(LOCATION);

    return 0;
}

signed main()
{
    random_perm_test(100);
    return 0;
}