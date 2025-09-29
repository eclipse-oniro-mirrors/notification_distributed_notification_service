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

#ifndef BASE_MOCK_INVOKE_COUNTING_H
#define BASE_MOCK_INVOKE_COUNTING_H

namespace OHOS {
namespace Notification {
class MockInvokeCounting {
public:
    static MockInvokeCounting& GetInstance()
    {
        static MockInvokeCounting mockInvokeCounting;
        return mockInvokeCounting;
    };

    void MockReSetCount()
    {
        g_mockCount = 0;
    };

    void MockSetCount()
    {
        g_mockCount++;
    };

    bool MockGetCount()
    {
        return g_mockCount;
    };

private:
    int32_t g_mockCount = 0;
};
}
}
#endif // BASE_MOCK_INVOKE_COUNTING_H