package com.hw;

import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;

public class MenuListener implements OnClickListener
{
	public HelloAndroid parent = null;
	
	public MenuListener(HelloAndroid ha)
	{
		parent = ha;
	}
	
	@Override
	public void onClick(DialogInterface dialog, int item)
	{
		switch(item)
		{
			case 0: parent.keyGen(); break;
			case 1: parent.keyGetServer(); break;
			case 2: parent.keySetServer(); break;
			case 3: parent.keyConnect(); break;
		}
	}

}
