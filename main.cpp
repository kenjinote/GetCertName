#pragma comment(lib,"crypt32")
#include <windows.h>

TCHAR szClassName[] = TEXT("Window");

BOOL GetCertName(LPCTSTR lpszFilePath, LPTSTR lpszCertName, INT nCertNameLength)
{
	HCERTSTORE hStore = NULL;
	HCRYPTMSG hMsg = NULL;
	PCCERT_CONTEXT pCertContext = NULL;
	BOOL fResult;
	BOOL fReturn = FALSE;
	DWORD dwEncoding, dwContentType, dwFormatType;
	PCMSG_SIGNER_INFO pSignerInfo = NULL;
	DWORD dwSignerInfo;
	CERT_INFO CertInfo;
	LPTSTR szName = NULL;
	__try
	{
		fResult = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
			lpszFilePath,
			CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
			CERT_QUERY_FORMAT_FLAG_BINARY,
			0,
			&dwEncoding,
			&dwContentType,
			&dwFormatType,
			&hStore,
			&hMsg,
			NULL);
		if (!fResult)
		{
			__leave;
		}
		fResult = CryptMsgGetParam(hMsg,
			CMSG_SIGNER_INFO_PARAM,
			0,
			NULL,
			&dwSignerInfo);
		if (!fResult)
		{
			__leave;
		}
		pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo);
		if (!pSignerInfo)
		{
			__leave;
		}
		fResult = CryptMsgGetParam(hMsg,
			CMSG_SIGNER_INFO_PARAM,
			0,
			(PVOID)pSignerInfo,
			&dwSignerInfo);
		if (!fResult)
		{
			__leave;
		}
		CertInfo.Issuer = pSignerInfo->Issuer;
		CertInfo.SerialNumber = pSignerInfo->SerialNumber;
		pCertContext = CertFindCertificateInStore(hStore,
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			0,
			CERT_FIND_SUBJECT_CERT,
			(PVOID)&CertInfo,
			NULL);
		if (!pCertContext)
		{
			__leave;
		}
		DWORD dwData;
		if (!(dwData = CertGetNameString(pCertContext,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			0,
			NULL,
			NULL,
			0)))
		{
			__leave;
		}
		szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));
		if (!szName)
		{
			__leave;
		}
		if (!(CertGetNameString(pCertContext,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			0,
			NULL,
			szName,
			dwData)))
		{
			__leave;
		}
		lstrcpyn(lpszCertName, szName, nCertNameLength);
		fReturn = TRUE;
	}
	__finally
	{
		if (szName != NULL) LocalFree(szName);
		if (pSignerInfo != NULL) LocalFree(pSignerInfo);
		if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
		if (hStore != NULL) CertCloseStore(hStore, 0);
		if (hMsg != NULL) CryptMsgClose(hMsg);
	}
	return fReturn;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static HWND hEdit;
	switch (msg)
	{
	case WM_CREATE:
		hEdit = CreateWindow(TEXT("EDIT"), 0, WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL | ES_READONLY, 10, 10, 512, 32, hWnd, 0, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		DragAcceptFiles(hWnd, TRUE);
		break;
	case WM_SIZE:
		MoveWindow(hEdit, 10, 10, LOWORD(lParam) - 20, 32, 1);
		break;
	case WM_DROPFILES:
		{
			SetWindowText(hEdit, 0);
			HDROP hDrop = (HDROP)wParam;
			TCHAR szFileName[MAX_PATH], szCertName[1024];
			UINT i;
			const UINT nFiles = DragQueryFile((HDROP)hDrop, 0xFFFFFFFF, NULL, 0);
			for (i = 0; i<nFiles; i++)
			{
				DragQueryFile(hDrop, i, szFileName, sizeof(szFileName));
				if (GetCertName(szFileName, szCertName, 1024))
				{
					SetWindowText(hEdit, szCertName);
				}
			}
			DragFinish(hDrop);
		}
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hWnd, msg, wParam, lParam);
	}
	return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPreInst, LPSTR pCmdLine, int nCmdShow)
{
	MSG msg;
	WNDCLASS wndclass = {
		CS_HREDRAW | CS_VREDRAW,
		WndProc,
		0,
		0,
		hInstance,
		0,
		LoadCursor(0, IDC_ARROW),
		(HBRUSH)(COLOR_WINDOW + 1),
		0,
		szClassName
	};
	RegisterClass(&wndclass);
	HWND hWnd = CreateWindow(
		szClassName,
		TEXT("ドラッグされたexe、dll、ocx、cab、msiの署名者名を取得する"),
		WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT,
		0,
		CW_USEDEFAULT,
		0,
		0,
		0,
		hInstance,
		0
		);
	ShowWindow(hWnd, SW_SHOWDEFAULT);
	UpdateWindow(hWnd);
	while (GetMessage(&msg, 0, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return msg.wParam;
}
