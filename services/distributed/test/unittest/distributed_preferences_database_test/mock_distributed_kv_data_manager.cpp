/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "distributed_kv_data_manager.h"

namespace {
    bool g_mockCloseKvStoreRet = true;
}

void MockCloseKvStore(bool mockRet)
{
    g_mockCloseKvStoreRet = mockRet;
}

namespace OHOS {
namespace DistributedKv {
DistributedKvDataManager::DistributedKvDataManager()
{}

DistributedKvDataManager::~DistributedKvDataManager()
{}
Status DistributedKvDataManager::GetSingleKvStore(const Options &options, const AppId &appId, const StoreId &storeId,
    std::shared_ptr<SingleKvStore> &singleKvStore)
{
    return Status::INVALID_ARGUMENT;
}

Status DistributedKvDataManager::CloseKvStore(const AppId &appId, const StoreId &storeId, int32_t subUser)
{
    if (false == g_mockCloseKvStoreRet) {
        return Status::INVALID_ARGUMENT;
    }
    return Status::SUCCESS;
}

Status DistributedKvDataManager::DeleteKvStore(const AppId &appId, const StoreId &storeId, const std::string &path,
    int32_t subUser)
{
    return Status::INVALID_ARGUMENT;
}
}  // namespace DistributedKv
}  // namespace OHOS