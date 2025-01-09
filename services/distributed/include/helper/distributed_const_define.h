/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_CONST_DEFINE_H
#define BASE_NOTIFICATION_DISTRIBUTED_CONST_DEFINE_H

#include <unordered_set>

namespace OHOS {
namespace Notification {

// Error code defined.
enum ErrorCode : int32_t {
    DISRTIBUED_ERR = 100,
    DISRTIBUED_SOCKET_CREATE_ERR,
    DISRTIBUED_SOCKET_LISTEN_ERR,
};

}
}
#endif // BASE_NOTIFICATION_DISTRIBUTED_CONST_DEFINE_H
