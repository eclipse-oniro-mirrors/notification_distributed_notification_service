/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_ANS_STANDARD_SERVICES_ANS_TEST_UNITEST_REMINDER_UT_CONSTANT_H
#define BASE_NOTIFICATION_ANS_STANDARD_SERVICES_ANS_TEST_UNITEST_REMINDER_UT_CONSTANT_H

#include <string>

namespace OHOS {
namespace Notification {
constexpr uint32_t NATIVE_TOKEN = 0;
constexpr uint32_t NON_NATIVE_TOKEN = 1;
constexpr uint32_t DLP_NATIVE_TOKEN = 2;
constexpr int32_t SYSTEM_APP_UID = 100;
constexpr int32_t NON_SYSTEM_APP_UID = 1000;
constexpr int32_t NON_BUNDLE_NAME_UID = 2000;
const std::string TEST_DEFUALT_BUNDLE = "bundleName";
constexpr int32_t TEST_SUBSCRIBE_USER_INIT = -1;
}  // namespace Notification
}  // namespace OHOS

#endif