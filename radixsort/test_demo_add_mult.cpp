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

#define fgh cout << "\n-------------------------\n";
#define foru(i, a, b) for (int i = a; i < b; ++i)
#define ford(i, a, b) for (int i = a; i > b; --i)

i64 Sh3_Bin_add_test(u64 n)
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

    BetaLibrary lib;
    BetaCircuit *cir = lib.int_int_add(64, 64, 64);
    cir->levelByAndDepth();

    u64 width = n;
    bool failed = false;

    using namespace aby3;

    auto aSize = cir->mInputs[0].size();
    auto bSize = cir->mInputs[1].size();
    auto cSize = cir->mOutputs[0].size();
    cout << "aSize = " << aSize << endl;

    Timer t;
    u32 MOD = 10;
    auto t0 = std::thread([&]()
                          {
                              auto i = 0;
                              i64Matrix a(width, 1), b(width, 1), c(width, 1);
                              
                              PRNG prng(ZeroBlock);
                              for (u64 i = 0; i < (u64)a.size(); ++i)
                              {
                                  a(i) = prng.get<i64>()%MOD;
                                  b(i) = prng.get<i64>()%MOD;

                               
                                  cout << "i = " << i << endl;
                                  cout << "a(i), b(i) = " << a(i) <<','<< b(i) << endl;
                                 
                              }
                              
                              Sh3Runtime rt(i, comms[i]);

                              sbMatrix A(width, aSize), B(width, bSize), C(width, cSize);

                              Sh3Encryptor enc;
                              enc.init(i, toBlock(i), toBlock(i + 1));

                              auto task = rt.noDependencies();
                              
                              t.setTimePoint("start");
                              enc.localBinMatrix(rt.noDependencies(), a, A).get();

                              task = enc.localBinMatrix(rt.noDependencies(), b, B);

                              Sh3BinaryEvaluator eval;

                              t.setTimePoint("eval");
                              task = eval.asyncEvaluate(task, cir, enc.mShareGen, {&A, &B}, {&C});
                              task.get();

                              t.setTimePoint("revealAll");
                              i64Matrix m(n, 1);
                              enc.revealAll(task, C, m).get();

                              fgh;
                              for (int i = 0; i < m.rows();++i)
                                  cout << (int)m(i,0) << endl;
                              fgh;
                              t.setTimePoint("done"); });

    auto routine = [&](int i)
    {
        PRNG prng;

        Sh3Runtime rt(i, comms[i]);

        sbMatrix A(width, aSize), B(width, bSize), C(width, cSize);

        Sh3Encryptor enc;
        enc.init(i, toBlock(i), toBlock((i + 1) % 3));

        auto task = rt.noDependencies();
        // queue up the operations
        enc.remoteBinMatrix(rt.noDependencies(), A).get();
        task = enc.remoteBinMatrix(rt.noDependencies(), B);

        Sh3BinaryEvaluator eval;

        task = eval.asyncEvaluate(task, cir, enc.mShareGen, {&A, &B}, {&C});
        // actually execute the computation
        task.get();

        i64Matrix m(C.rows(), 1);
        enc.revealAll(task, C, m).get();
    };

    auto t1 = std::thread(routine, 1);
    auto t2 = std::thread(routine, 2);

    t0.join();
    t1.join();
    t2.join();

    auto comm0 = (comms[0].mNext.getTotalDataSent() + comms[0].mNext.getTotalDataSent());
    auto comm1 = (comms[1].mNext.getTotalDataSent() + comms[1].mNext.getTotalDataSent());
    auto comm2 = (comms[2].mNext.getTotalDataSent() + comms[2].mNext.getTotalDataSent());
    std::cout << "n = " << n << "   " << comm0 + comm1 + comm2 << "\n"
              << t << std::endl;

    if (failed)
        throw std::runtime_error(LOCATION);

    return 0;
}

i64 Sh3_Int_Matrix_test(u64 n, u64 m)
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

    using namespace aby3;

    Timer t;
    u32 MOD = 10;
    auto t0 = std::thread([&]()
                          {
                              auto i = 0;
                              i64Matrix a(n, m), b(n, m);
                              
                              PRNG prng(ZeroBlock);
                              foru(i,0,n) foru(j,0,m) 
                              {
                                a(i,j) = prng.get<i64>() % MOD;
                                b(i,j) = prng.get<i64>() % MOD;
                              }
                              fgh;
                              cout << "a:\n";
                              foru(i, 0, n) foru(j, 0, m) cout << a(i, j) << " \n"[j == m - 1];
                              fgh;
                              cout << "b:\n";
                              foru(i, 0, n) foru(j, 0, m) cout << b(i, j) << " \n"[j == m - 1];
                              fgh;
                              Sh3Runtime rt(i, comms[i]);

                              si64Matrix A(n,m), B(n,m), C(n,m);

                              Sh3Encryptor enc;
                              enc.init(i, comms[i],sysRandomSeed());

                              auto task = rt.noDependencies();
                              
                              t.setTimePoint("start");
                              enc.localIntMatrix(rt.noDependencies(), a, A).get();
                              task = enc.localIntMatrix(rt.noDependencies(), b, B);
                              cout << "yes " << i << endl;
                              Sh3Evaluator eval;
                              eval.init(i, comms[i], sysRandomSeed());

                              t.setTimePoint("eval");
                              task = eval.asyncMul(task, A, B, C);
                              task.get();

                              t.setTimePoint("revealAll");

                              i64Matrix c(n, m);
                              enc.revealAll(task, C, c).get();

                              fgh;
                            //   foru(i, 0, n)
                            //     foru(j, 0, m) cout << (i64)c(i, j) << " \n"[j == m-1];
                              cout << c << endl;
                            
                              fgh;
                              t.setTimePoint("done"); });

    auto routine = [&](int i)
    {
        PRNG prng;

        Sh3Runtime rt(i, comms[i]);

        si64Matrix A(n, m), B(n, m), C(n, m);

        Sh3Encryptor enc;
        enc.init(i, comms[i], sysRandomSeed());

        auto task = rt.noDependencies();
        // queue up the operations
        enc.remoteIntMatrix(rt.noDependencies(), A).get();
        task = enc.remoteIntMatrix(rt.noDependencies(), B);
        cout << "yes " << i << endl;
        Sh3Evaluator eval;
        eval.init(i, comms[i], sysRandomSeed());
        task = eval.asyncMul(task, A, B, C);

        // actually execute the computation
        task.get();
        i64Matrix c(n, m);
        enc.revealAll(task, C, c).get();
    };

    auto t1 = std::thread(routine, 1);
    auto t2 = std::thread(routine, 2);

    t0.join();
    t1.join();
    t2.join();

    auto comm0 = (comms[0].mNext.getTotalDataSent() + comms[0].mNext.getTotalDataSent());
    auto comm1 = (comms[1].mNext.getTotalDataSent() + comms[1].mNext.getTotalDataSent());
    auto comm2 = (comms[2].mNext.getTotalDataSent() + comms[2].mNext.getTotalDataSent());
    std::cout << "n = " << n << "   " << comm0 + comm1 + comm2 << "\n"
              << t << std::endl;

    if (failed)
        throw std::runtime_error(LOCATION);

    return 0;
}

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

    using namespace aby3;

    Timer t;
    u32 MOD = 10;
    auto t0 = std::thread([&]()
                          {
                              auto i = 0;
                              vector<i64> a(n),b(n);

                              PRNG prng(ZeroBlock);
                              foru(i,0,n) a[i] = prng.get<i64>() % MOD;
                              foru(i,0,n) b[i] = prng.get<i64>() % MOD;
                              
                              fgh;
                              cout << "a:\n";
                              foru(i, 0, n) cout << a[i] << " "[i == n - 1];
                              fgh;
                              cout << "b:\n";
                              foru(i, 0, n) cout << b[i] << " "[i == n - 1];
                              fgh;

                              Sh3Runtime rt(i, comms[i]);

                              vector<si64> A(n),B(n);

                              Sh3Encryptor enc;
                              enc.init(i, comms[i],sysRandomSeed());

                              auto task = rt.noDependencies();
                              
                              t.setTimePoint("start");
                              foru(i,0,n) enc.localInt(rt.noDependencies(), a[i], A[i]).get();
                              foru(i,0,n) enc.localInt(rt.noDependencies(), b[i], B[i]).get();
                              
                              cout << "yes " << i << endl;

                              Sh3Evaluator eval;
                              eval.init(i, comms[i], sysRandomSeed());

                              t.setTimePoint("eval");
                              vector<si64> C(n);
                              foru(i, 0, n) task = eval.asyncMul(task, A[i], B[i], C[i]);
                              task.get();

                              t.setTimePoint("revealAll");

                              vector<i64> c(n);
                              foru(i,0,n) enc.revealAll(task, C[i], c[i]).get();

                              fgh;
                              foru(i, 0, n) cout << c[i] << " \n"[i == n - 1];
                              fgh;
                              t.setTimePoint("done"); });

    auto routine = [&](int i)
    {
        PRNG prng;

        Sh3Runtime rt(i, comms[i]);

        vector<i64> a(n), b(n);

        Sh3Encryptor enc;
        enc.init(i, comms[i], sysRandomSeed());

        auto task = rt.noDependencies();
        vector<si64> A(n), B(n);
        // queue up the operations
        foru(i, 0, n) enc.remoteInt(rt.noDependencies(), A[i]).get();
        foru(i, 0, n) enc.remoteInt(rt.noDependencies(), B[i]).get();

        cout << "yes " << i << endl;

        Sh3Evaluator eval;
        eval.init(i, comms[i], sysRandomSeed());
        vector<si64> C(n);
        foru(i, 0, n) task = eval.asyncMul(task, A[i], B[i], C[i]);
        task.get();

        vector<i64> c(n);
        foru(i, 0, n) enc.revealAll(task, C[i], c[i]).get();
    };

    auto t1 = std::thread(routine, 1);
    auto t2 = std::thread(routine, 2);

    t0.join();
    t1.join();
    t2.join();

    auto comm0 = (comms[0].mNext.getTotalDataSent() + comms[0].mNext.getTotalDataSent());
    auto comm1 = (comms[1].mNext.getTotalDataSent() + comms[1].mNext.getTotalDataSent());
    auto comm2 = (comms[2].mNext.getTotalDataSent() + comms[2].mNext.getTotalDataSent());
    std::cout << "n = " << n << "   " << comm0 + comm1 + comm2 << "\n"
              << t << std::endl;

    if (failed)
        throw std::runtime_error(LOCATION);

    return 0;
}

signed main()
{
    Sh3_Bin_add_test(3);
    // Sh3_Int_Matrix_test(2, 2);
    // Sh3_Int_Vector_test(3);
    return 0;
}