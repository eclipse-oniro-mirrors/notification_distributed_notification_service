/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hitrace_util.h"

#include "hitrace/hitracechain.h"
 
namespace OHOS {
namespace Notification {
static const std::string TRACE_CHAIN_NAME = "distributed_notification_service";
 
TraceChainUtil::TraceChainUtil()
{
    auto oldTraceId = OHOS::HiviewDFX::HiTraceChain::GetId();
    if (oldTraceId.IsValid()) {
        return;
    }
    traceId = OHOS::HiviewDFX::HiTraceChain::Begin(TRACE_CHAIN_NAME, HiTraceFlag::HITRACE_FLAG_INCLUDE_ASYNC |
        HiTraceFlag::HITRACE_FLAG_NO_BE_INFO |
        HiTraceFlag::HITRACE_FLAG_DONOT_CREATE_SPAN);
}
 
TraceChainUtil::~TraceChainUtil()
{
    if (traceId.IsValid()) {
        OHOS::HiviewDFX::HiTraceChain::End(traceId);
    }
}
 
}  // namespace Notification
}  // namespace OHOS