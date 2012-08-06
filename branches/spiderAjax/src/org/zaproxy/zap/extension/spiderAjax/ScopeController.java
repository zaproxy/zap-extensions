package org.zaproxy.zap.extension.spiderAjax;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
public class ScopeController implements SessionChangedListener {

	@Override
	public void sessionAboutToChange(Session arg0) {
		// TODO Auto-generated method stub
		System.out.println("tessssssssssssssssst4");

	}

	@Override
	public void sessionChanged(Session arg0) {
		// TODO Auto-generated method stub
		System.out.println("tessssssssssssssssst3");

	}

	@Override
	public void sessionModeChanged(Mode arg0) {
		// TODO Auto-generated method stub
		System.out.println("tessssssssssssssssst2");

	}

	@Override
	public void sessionScopeChanged(Session arg0) {
		// TODO Auto-generated method stub
		System.out.println("tessssssssssssssssst");
	}

}
