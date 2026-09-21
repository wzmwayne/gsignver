package kms

import "testing"

func TestCodeHashUsesPepperAndNamespace(t *testing.T) {
	k1, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	k2, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h1 := k1.CodeHash("com.a", "ABCDE-FGHIJ")
	if h1 == k2.CodeHash("com.a", "ABCDE-FGHIJ") {
		t.Fatal("不同 pepper 必须产生不同摘要，否则 pepper 未参与运算")
	}
	if k1.CodeHash("com.a", "ABCDE-FGHIJ") != h1 {
		t.Fatal("同一输入摘要必须稳定")
	}
	if k1.CodeHash("com.a", "abcde-fghij") != h1 {
		t.Fatal("归一化应忽略大小写与连字符")
	}
	if k1.CodeHash("com.b", "ABCDE-FGHIJ") == h1 {
		t.Fatal("app_id 必须参与摘要，否则跨应用会撞键")
	}
	if len(h1) != 64 {
		t.Fatalf("摘要应为 32 字节 hex，得到 %d 字符", len(h1))
	}
}
