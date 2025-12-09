/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef ADVANCED_DATASHARE_HELPER_DATA_OBSERVER_H
#define ADVANCED_DATASHARE_HELPER_DATA_OBSERVER_H

#include <vector>

#include "data_ability_observer_stub.h"
#include "uri.h"

namespace OHOS {
namespace Notification {
class AdvancedDatashareHelperDataObserver : public AAFwk::DataAbilityObserverStub {
public:
    AdvancedDatashareHelperDataObserver(Uri uri, std::vector<std::string> keys);
    ~AdvancedDatashareHelperDataObserver();
    Uri GetUri();
    void OnChange() override;

private:
    Uri uri_;
    std::vector<std::string> keys_;
};
} // namespace Notification
} // namespace OHOS
#endif // ADVANCED_DATASHARE_HELPER_DATA_OBSERVER_H
