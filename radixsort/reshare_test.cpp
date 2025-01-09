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

void localIntMatrix(CommPkg &comm, const i64Matrix &m, si64Matrix &ret)
{
    for (i64 i = 0; i < ret.mShares[0].size(); ++i)
        ret.mShares[0](i) = m(i);

    comm.mNext.asyncSendCopy(ret.mShares[0].data(), ret.mShares[0].size());
    comm.mPrev.recv(ret.mShares[1].data(), ret.mShares[1].size());
}

void remoteIntMatrix(CommPkg &comm, si64Matrix &ret)
{

    for (i64 i = 0; i < ret.mShares[0].size(); ++i)
        ret.mShares[0](i) = 0;

    comm.mNext.asyncSendCopy(ret.mShares[0].data(), ret.mShares[0].size());
    comm.mPrev.recv(ret.mShares[1].data(), ret.mShares[1].size());
}
i64 reshare_test(u64 n)
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
            // t.setTimePoint("add" + to_string(idx));
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

        /* Input datas */
        si64Matrix A(n, 1);
        IFparty0 t.setTimePoint("start");

        idx == 0 ? localIntMatrix(comms[idx], a, A) : remoteIntMatrix(comms[idx], A);

        t.setTimePoint("input" + to_string(idx));
        /*---------------------------------reshare--------------------------------*/
        ReshareVec(A, 0);
        t.setTimePoint("reshare" + to_string(idx));
        i64Matrix ttt1(n, 1);
        ttt1 = enc.revealAll(comms[idx], A);
        IFparty0
        {
            cout << "reshared_A:\n";
            foru(i, 0, n) cout << ttt1(i) << " \n"[i == n - 1];
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
    reshare_test(100);
    return 0;
}