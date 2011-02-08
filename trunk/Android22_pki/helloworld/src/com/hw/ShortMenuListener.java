package com.hw;

import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;

public class ShortMenuListener implements OnClickListener
{
	public HelloAndroid parent = null;
	
	public ShortMenuListener(HelloAndroid ha)
	{
		parent = ha;
	}
	
	@Override
	public void onClick(DialogInterface dialog, int item)
	{
		switch(item)
		{
			case 0: parent.keyGen(); break;
			case 1: parent.keyLoadFromFile(); break;
		}
	}

}
