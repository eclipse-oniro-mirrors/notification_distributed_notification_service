/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef ANS_DELAYED_SINGLETON_REPOSITORY_H
#define ANS_DELAYED_SINGLETON_REPOSITORY_H

#include <string>
#include "bundle_manager_adapter.h"
#include "ans_inner_errors.h"
#include "ibundle_manager_repository.h"
#include "account_manager_repository_impl.h"
#include "bundle_manager_repository_impl.h"
#include "bundle_service_connector.h"

namespace OHOS {
namespace Notification {
namespace Infra {
class DelayedSingletonContainer {
public:
    static IBundleManagerRepository* GetBundleManagerRepository() {
        static auto instance = std::make_unique<BundleManagerRepositoryImpl>(
            BundleServiceConnector::GetInstance().get(),
            std::make_unique<AccountManagerRepositoryImpl>()
        );
        return instance.get();
    }
private:
    DelayedSingletonContainer() = delete;
};

} // namespace Infra
} // namespace Notification
} // namespace OHOS
#endif
