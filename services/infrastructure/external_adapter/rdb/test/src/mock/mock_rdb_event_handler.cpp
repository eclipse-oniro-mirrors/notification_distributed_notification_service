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

#include "mock_rdb_event_handler.h"

namespace OHOS::Notification::Infra {
MockRdbEventHandler::MockRdbEventHandler(const std::string &name, int32_t ret, bool enabled)
    : name_(name), ret_(ret)
{
    enabled_ = enabled;
}

int32_t MockRdbEventHandler::OnCreate(NativeRdb::RdbStore &)
{
    return ret_;
}

int32_t MockRdbEventHandler::OnUpgrade(NativeRdb::RdbStore &, int32_t, int32_t)
{
    return ret_;
}

int32_t MockRdbEventHandler::OnDowngrade(NativeRdb::RdbStore &, int32_t, int32_t)
{
    return ret_;
}

int32_t MockRdbEventHandler::OnOpen(NativeRdb::RdbStore &)
{
    return ret_;
}

int32_t MockRdbEventHandler::OnCorruption(const std::string &)
{
    return ret_;
}

std::string MockRdbEventHandler::GetHandlerName() const
{
    return name_;
}

bool MockRdbEventHandler::IsEnabled() const
{
    return enabled_;
}

void MockRdbEventHandler::SetEnabled(bool enabled)
{
    enabled_ = enabled;
}

void MockRdbEventHandler::SetReturnCode(int32_t ret)
{
    ret_ = ret;
}
} // namespace OHOS::Notification::Infra