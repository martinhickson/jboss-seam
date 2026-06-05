package org.jboss.seam.jsf;

import java.util.Collection;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;

import jakarta.el.ELContextListener;
import jakarta.el.ELException;
import jakarta.el.ELResolver;
import jakarta.el.ExpressionFactory;
import jakarta.el.ValueExpression;
import jakarta.faces.FacesException;
import jakarta.faces.application.Application;
import jakarta.faces.application.NavigationHandler;
import jakarta.faces.application.ProjectStage;
import jakarta.faces.application.Resource;
import jakarta.faces.application.ResourceHandler;
import jakarta.faces.application.StateManager;
import jakarta.faces.application.ViewHandler;
import jakarta.faces.component.UIComponent;
import jakarta.faces.component.behavior.Behavior;
import jakarta.faces.component.search.SearchExpressionHandler;
import jakarta.faces.component.search.SearchKeywordResolver;
import jakarta.faces.context.FacesContext;
import jakarta.faces.convert.Converter;
import jakarta.faces.event.ActionListener;
import jakarta.faces.event.SystemEvent;
import jakarta.faces.event.SystemEventListener;
import jakarta.faces.validator.Validator;

import org.jboss.seam.Component;
import org.jboss.seam.contexts.Contexts;
import org.jboss.seam.core.Init;
import org.jboss.seam.el.SeamExpressionFactory;

/**
 * Proxies the JSF Application object, and adds all kinds
 * of tasty extras.
 *
 * @author Gavin King
 */
@SuppressWarnings("deprecation")
public class SeamApplication extends Application {

    protected final Application delegate;

    public SeamApplication(Application delegate) {
        this.delegate = delegate;
    }

    public Application getDelegate() {
        return delegate;
    }

    @Override
    public ELResolver getELResolver() {
        return delegate.getELResolver();
    }

    @Override
    public void addComponent(String componentType, String componentClass) {
        delegate.addComponent(componentType, componentClass);
    }

    @Override
    public void addConverter(String converterId, String converterClass) {
        delegate.addConverter(converterId, converterClass);
    }

    @Override
    public void addConverter(Class<?> targetClass, String converterClass) {
        delegate.addConverter(targetClass, converterClass);
    }

    @Override
    public void addValidator(String validatorId, String validatorClass) {
        delegate.addValidator(validatorId, validatorClass);
    }

    @Override
    public UIComponent createComponent(String componentType) throws FacesException {
        return delegate.createComponent(componentType);
    }

    @Override
    public UIComponent createComponent(FacesContext context, String componentType, String rendererType) {
        return delegate.createComponent(context, componentType, rendererType);
    }

    @Override
    public UIComponent createComponent(FacesContext context, Resource resource) {
        return delegate.createComponent(context, resource);
    }

    @Override
    public Converter createConverter(String converterId) {
        if (Contexts.isApplicationContextActive()) {
            String name = Init.instance().getConverters().get(converterId);
            if (name != null) {
                return (Converter) Component.getInstance(name);
            }
        }
        return delegate.createConverter(converterId);
    }

    @Override
    public Converter createConverter(Class<?> targetClass) {
        Converter converter = null;
        if (Contexts.isApplicationContextActive()) {
            converter = new ConverterLocator(targetClass).getConverter();
        }
        if (converter == null) {
            converter = delegate.createConverter(targetClass);
        }
        if (converter == null && targetClass != null && java.util.Date.class.isAssignableFrom(targetClass)) {
            converter = delegate.createConverter("jakarta.faces.DateTime");
        }
        return converter;
    }

    private class ConverterLocator {

        private Map<Class, String> converters;
        private Class targetClass;
        private Converter converter;

        public ConverterLocator(Class targetClass) {
            converters = Init.instance().getConvertersByClass();
            this.targetClass = targetClass;
        }

        public Converter getConverter() {
            if (converter == null) {
                locateConverter(targetClass);
            }
            return converter;
        }

        private Converter createConverter(Class clazz) {
            return (Converter) Component.getInstance(converters.get(clazz));
        }

        private void locateConverter(Class clazz) {
            if (converters.containsKey(clazz)) {
                converter = createConverter(clazz);
                return;
            }

            for (Class iface : clazz.getInterfaces()) {
                if (converters.containsKey(iface)) {
                    converter = createConverter(iface);
                    return;
                } else {
                    locateConverter(iface);
                    if (converter != null) {
                        return;
                    }
                }
            }

            Class superClass = clazz.getSuperclass();
            if (converters.containsKey(superClass)) {
                converter = createConverter(superClass);
                return;
            } else if (superClass != null) {
                locateConverter(superClass);
            }
        }
    }

    @Override
    public Validator createValidator(String validatorId) throws FacesException {
        if (Contexts.isApplicationContextActive()) {
            String name = Init.instance().getValidators().get(validatorId);
            if (name != null) {
                return (Validator) Component.getInstance(name);
            }
        }
        return delegate.createValidator(validatorId);
    }

    @Override
    public Iterator<String> getComponentTypes() {
        return delegate.getComponentTypes();
    }

    @Override
    public Iterator<String> getConverterIds() {
        return delegate.getConverterIds();
    }

    @Override
    public Iterator<Class<?>> getConverterTypes() {
        return delegate.getConverterTypes();
    }

    @Override
    public Locale getDefaultLocale() {
        return delegate.getDefaultLocale();
    }

    @Override
    public String getDefaultRenderKitId() {
        return delegate.getDefaultRenderKitId();
    }

    @Override
    public String getMessageBundle() {
        return delegate.getMessageBundle();
    }

    @Override
    public NavigationHandler getNavigationHandler() {
        return delegate.getNavigationHandler();
    }

    @Override
    public StateManager getStateManager() {
        return delegate.getStateManager();
    }

    @Override
    public Iterator<Locale> getSupportedLocales() {
        return delegate.getSupportedLocales();
    }

    @Override
    public Iterator<String> getValidatorIds() {
        return delegate.getValidatorIds();
    }

    @Override
    public ViewHandler getViewHandler() {
        return delegate.getViewHandler();
    }

    @Override
    public void setActionListener(ActionListener listener) {
        delegate.setActionListener(listener);
    }

    @Override
    public void setDefaultLocale(Locale locale) {
        delegate.setDefaultLocale(locale);
    }

    @Override
    public void setDefaultRenderKitId(String renderKitId) {
        delegate.setDefaultRenderKitId(renderKitId);
    }

    @Override
    public void setMessageBundle(String bundle) {
        delegate.setMessageBundle(bundle);
    }

    @Override
    public void setNavigationHandler(NavigationHandler handler) {
        delegate.setNavigationHandler(handler);
    }

    @Override
    public void setStateManager(StateManager manager) {
        delegate.setStateManager(manager);
    }

    @Override
    public void setSupportedLocales(Collection<Locale> locales) {
        delegate.setSupportedLocales(locales);
    }

    @Override
    public void setViewHandler(ViewHandler handler) {
        delegate.setViewHandler(handler);
    }

    @Override
    public void addELContextListener(ELContextListener elcl) {
        delegate.addELContextListener(elcl);
    }

    @Override
    public void addELResolver(ELResolver elr) {
        delegate.addELResolver(elr);
    }

    @Override
    public UIComponent createComponent(ValueExpression ve, FacesContext fc, String id) throws FacesException {
        return delegate.createComponent(ve, fc, id);
    }

    @Override
    public <T> T  evaluateExpressionGet(FacesContext ctx, String expr, Class<? extends T> type) throws ELException {
        return delegate.evaluateExpressionGet(ctx, expr, type);
    }

    @Override
    public ELContextListener[] getELContextListeners() {
        return delegate.getELContextListeners();
    }

    @Override
    public ExpressionFactory getExpressionFactory() {
        return new SeamExpressionFactory(delegate.getExpressionFactory());
    }

    @Override
    public ResourceBundle getResourceBundle(FacesContext fc, String name) {
        return delegate.getResourceBundle(fc, name);
    }

    @Override
    public void removeELContextListener(ELContextListener elcl) {
        delegate.removeELContextListener(elcl);
    }

    @Override
    public String toString() {
        return "SeamApplication(" + delegate + ")";
    }

    @Override
    public void publishEvent(FacesContext context, Class<? extends SystemEvent> systemEventClass, Object source) {
        delegate.publishEvent(context, systemEventClass, source);
    }

    @Override
    public void publishEvent(FacesContext context, Class<? extends SystemEvent> systemEventClass, Class<?> sourceBaseType,
            Object source) {
        delegate.publishEvent(context, systemEventClass, sourceBaseType, source);
    }

    @Override
    public Behavior createBehavior(String behaviorId) throws FacesException {
        return delegate.createBehavior(behaviorId);
    }

    @Override
    public Iterator<String> getBehaviorIds() {
        return delegate.getBehaviorIds();
    }

    @Override
    public ResourceHandler getResourceHandler() {
        return delegate.getResourceHandler();
    }

    @Override
    public void setResourceHandler(ResourceHandler resourceHandler) {
        delegate.setResourceHandler(resourceHandler);
    }

    @Override
    public SearchExpressionHandler getSearchExpressionHandler() {
        return delegate.getSearchExpressionHandler();
    }

    @Override
    public void setSearchExpressionHandler(SearchExpressionHandler searchExpressionHandler) {
        delegate.setSearchExpressionHandler(searchExpressionHandler);
    }

    @Override
    public SearchKeywordResolver getSearchKeywordResolver() {
        return delegate.getSearchKeywordResolver();
    }

    @Override
    public void addSearchKeywordResolver(SearchKeywordResolver resolver) {
        delegate.addSearchKeywordResolver(resolver);
    }

    @Override
    public ProjectStage getProjectStage() {
        return delegate.getProjectStage();
    }

    @Override
    public void addBehavior(String behaviorId, String behaviorClass) {
        delegate.addBehavior(behaviorId, behaviorClass);
    }

    @Override
    public UIComponent createComponent(ValueExpression componentExpression, FacesContext context, String componentType,
            String rendererType) {
        return delegate.createComponent(componentExpression, context, componentType, rendererType);
    }

    @Override
    public void addDefaultValidatorId(String validatorId) {
        delegate.addDefaultValidatorId(validatorId);
    }

    @Override
    public Map<String, String> getDefaultValidatorInfo() {
        return delegate.getDefaultValidatorInfo();
    }

    @Override
    public void subscribeToEvent(Class<? extends SystemEvent> systemEventClass, Class<?> sourceClass,
            SystemEventListener listener) {
        delegate.subscribeToEvent(systemEventClass, sourceClass, listener);
    }

    @Override
    public void subscribeToEvent(Class<? extends SystemEvent> systemEventClass, SystemEventListener listener) {
        delegate.subscribeToEvent(systemEventClass, listener);
    }

    @Override
    public void unsubscribeFromEvent(Class<? extends SystemEvent> systemEventClass, Class<?> sourceClass,
            SystemEventListener listener) {
        delegate.unsubscribeFromEvent(systemEventClass, sourceClass, listener);
    }

    @Override
    public void unsubscribeFromEvent(Class<? extends SystemEvent> systemEventClass, SystemEventListener listener) {
        delegate.unsubscribeFromEvent(systemEventClass, listener);
    }

    @Override
    public ActionListener getActionListener() {
        return delegate.getActionListener();
    }
}
