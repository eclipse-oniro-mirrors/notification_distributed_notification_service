/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_ANS_SERVICES_TELEPHONY_EXTENSION_WRAPPER_H
#define BASE_NOTIFICATION_ANS_SERVICES_TELEPHONY_EXTENSION_WRAPPER_H

#include <string>

#include "singleton.h"
#include "datashare_helper.h"

namespace OHOS::Notification {
class TelExtensionWrapper final {
    DECLARE_DELAYED_SINGLETON(TelExtensionWrapper);
public:
    void InitTelExtentionWrapper();
    void CloseTelExtentionWrapper();
    typedef ErrCode (*GET_CALLER_INDEX)(std::shared_ptr<DataShare::DataShareResultSet> resultSet, std::string compNum);
    ErrCode GetCallerIndex(std::shared_ptr<DataShare::DataShareResultSet> resultSet, std::string compNum);
private:
    void* telephonyCustHandle_ = nullptr;
    GET_CALLER_INDEX getCallerIndex_ = nullptr;
};

#define TEL_EXTENTION_WRAPPER ::OHOS::DelayedSingleton<TelExtensionWrapper>::GetInstance()
} // namespace OHOS::Notification
#endif  // BASE_NOTIFICATION_ANS_SERVICES_TELEPHONY_EXTENSION_WRAPPER_H