/* 逐元素乘法 */
Sh3Task Sh3Evaluator::asyncEleWiseMul(Sh3Task dependency, const si64Matrix &A, const si64Matrix &B, si64Matrix &C)
{
    return dependency.then([&](CommPkg &comm, Sh3Task self)
                           {
			    // C.mShares[0].resizeLike(A.mShares[0]);
				for (u64 i = 0; i < A.size(); ++i)
					C.mShares[0](i) = A.mShares[0](i) * B.mShares[0](i)
									+ A.mShares[0](i) * B.mShares[1](i)
									+ A.mShares[1](i) * B.mShares[0](i);
						
				for (u64 i = 0; i < C.size(); ++i)
				{
					C.mShares[0](i) += mShareGen.getShare();
				}

				C.mShares[1].resizeLike(C.mShares[0]);

				comm.mNext.asyncSendCopy(C.mShares[0].data(), C.mShares[0].size());
				auto fu = comm.mPrev.asyncRecv(C.mShares[1].data(), C.mShares[1].size()).share();

				self.then([fu = std::move(fu)](CommPkg& comm, Sh3Task& self){
					fu.get();
				}); })
        .getClosure();
}