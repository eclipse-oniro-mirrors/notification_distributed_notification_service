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

#ifndef ANS_BUNDLE_MANAGER_CONNECTOR_H
#define ANS_BUNDLE_MANAGER_CONNECTOR_H

#include <memory>
#include "remote_death_recipient.h"

namespace OHOS {
namespace Notification {
namespace Infra {
class BundleServiceConnector {
public:
    explicit BundleServiceConnector();

    ~BundleServiceConnector();
    
    sptr<AppExecFwk::IBundleMgr> GetBundleManager();
    
private:
    void Connect();
    void Disconnect();
    void OnRemoteDied(const wptr<IRemoteObject> &object);
    
    sptr<AppExecFwk::IBundleMgr> bundleMgr_;
    std::mutex connectionMutex_;
    sptr<RemoteDeathRecipient> deathRecipient_;
};
} // namespace Infra
} // namespace Notification
} // namespace OHOS
#endif
